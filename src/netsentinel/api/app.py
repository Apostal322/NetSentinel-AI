"""FastAPI service over the inference engine, event store and offline replay.

Security posture (see docs/security/threat_model.md):
* binds to 127.0.0.1 by default (`netsentinel serve`); not intended for internet exposure;
* request bodies are bounded (batch <= MAX_BATCH flows, unknown fields rejected);
* replay only reads `.parquet` files inside the configured replay directory (no arbitrary
  paths); starting/cancelling a replay requires the admin token
  (env NETSENTINEL_ADMIN_TOKEN; if unset, admin endpoints are disabled);
* `POST /analyze` (admin token) accepts one PCAP/pcapng/Zeek conn.log upload, size-capped
  while streaming (MAX_UPLOAD_BYTES), stored under a random temp name, parsed only by the
  defensive pure-Python readers (no external tools, no shell), and deleted afterwards;
* detection only: no endpoint blocks traffic or changes network state.
"""

from __future__ import annotations

import hmac
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated

import polars as pl
from fastapi import Depends, FastAPI, Header, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from netsentinel import __version__
from netsentinel.inference.schema import FlowRecord, Prediction

log = logging.getLogger(__name__)
MAX_BATCH = 1000
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


class Settings(BaseModel):
    bundle_dir: Path
    events_db: Path = Path("artifacts/events.sqlite")
    replay_dir: Path = Path("data/interim/ids2018")
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    calibration_dir: Path | None = None  # local behaviour profile (netsentinel calibrate)
    appid_dir: Path | None = None  # application classifier artifact
    threat_policy: str = "unverified"  # supervised verdicts never escalate unless trusted


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flows: list[FlowRecord] = Field(min_length=1, max_length=MAX_BATCH)


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    day: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$", description="ingested capture day")
    start: datetime | None = None
    end: datetime | None = None
    max_events: int = Field(default=20_000, ge=1, le=200_000)
    speed: float = Field(default=0.0, ge=0, le=10_000)


class IncidentStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(
        pattern=r"^(new|investigating|acknowledged|resolved|insufficient_evidence)$"
    )
    note: str = Field(default="", max_length=500)


def _flows_to_frame(flows: list[FlowRecord]) -> pl.DataFrame:
    rows = []
    for f in flows:
        row = {k: v for k, v in f.features.items()}
        row.update(timestamp=f.timestamp.replace(tzinfo=None), dst_port=f.dst_port,
                   protocol=f.protocol, flow_duration=f.flow_duration)  # fmt: skip
        rows.append(row)
    return pl.DataFrame(rows, infer_schema_length=None)


def create_app(settings: Settings) -> FastAPI:
    from netsentinel.inference.engine import Engine
    from netsentinel.storage.events import EventStore
    from netsentinel.streaming.replay import ReplayConfig, Replayer

    app = FastAPI(title="NetSentinel AI", version=__version__,
                  description="Detection-only network flow intelligence API (offline replay "
                              "and on-demand scoring). Not a blocking/IPS system.")  # fmt: skip
    state: dict = {"engine": None, "error": None, "pipeline": None}
    try:
        state["engine"] = Engine(settings.bundle_dir)
    except Exception as exc:  # noqa: BLE001 - reported by /ready instead of crashing
        log.exception("failed to load bundle")
        state["error"] = f"{type(exc).__name__}: {exc}"
    if state["engine"] is not None:
        from netsentinel.inference.pipeline import AnalysisPipeline

        try:  # refuses corrupt/incompatible artifacts; reported by /ready
            state["pipeline"] = AnalysisPipeline(settings.bundle_dir, settings.calibration_dir,
                                                 settings.appid_dir, settings.threat_policy,
                                                 engine=state["engine"])  # fmt: skip
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to load calibration / application classifier")
            state["error"] = f"{type(exc).__name__}: {exc}"
            state["engine"] = None
    store = EventStore(settings.events_db)
    replayer = Replayer(state["engine"], store) if state["engine"] else None

    def engine() -> Engine:
        if state["engine"] is None:
            raise HTTPException(503, f"model bundle not loaded: {state['error']}")
        return state["engine"]

    def admin(x_admin_token: Annotated[str | None, Header()] = None) -> None:
        expected = os.environ.get("NETSENTINEL_ADMIN_TOKEN")
        if not expected:
            raise HTTPException(403, "admin endpoints disabled (NETSENTINEL_ADMIN_TOKEN unset)")
        if not x_admin_token or not hmac.compare_digest(x_admin_token, expected):
            raise HTTPException(401, "invalid admin token")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/ready")
    def ready() -> dict:
        if state["engine"] is None:
            raise HTTPException(503, state["error"] or "not ready")
        return {"status": "ready", "bundle": state["engine"].bundle_id}

    @app.get("/models")
    def models() -> dict:
        out = {**engine().manifest}
        pipe = state["pipeline"]
        out["calibration"] = pipe.calibration if pipe else None
        out["application_classifier"] = pipe.classifier_manifest if pipe else None
        out["threat_mode"] = pipe.threat_mode if pipe else None
        out["threat_policy"] = settings.threat_policy
        return out

    @app.get("/behavior")
    def behavior(
        level: str | None = Query(None, pattern="^(global|device|service)$"),
        anomalous_only: bool = False,
        source: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
        offset: int = Query(0, ge=0),
    ) -> list[dict]:
        """Scored behaviour windows (local-baseline deviations; not attack verdicts)."""
        return store.behavior(level, anomalous_only, source, limit, offset)

    @app.get("/baseline")
    def baseline() -> dict:
        """Metadata of the loaded local calibration: status, mode, period, thresholds and their
        sampling uncertainty (fpr_upper95). 404 when no calibration is loaded."""
        pipe = state["pipeline"]
        man = pipe.calibration if pipe else None
        if not man:
            raise HTTPException(404, "no behaviour calibration loaded")
        levels = {lv: {"threshold": m.get("threshold"),
                       "threshold_method": m.get("threshold_method"),
                       "holdout_windows": m.get("holdout_windows"),
                       "expected_fpr": (m.get("threshold_diagnostics") or {}).get("expected_fpr"),
                       "fpr_upper95": (m.get("threshold_diagnostics") or {}).get("fpr_upper95"),
                       "reliable": (m.get("threshold_diagnostics") or {}).get("reliable"),
                       "warnings": m.get("warnings")}
                  for lv, m in (man.get("levels") or {}).items()}  # fmt: skip
        return {"calibration_id": man["calibration_id"], "status": man.get("status"),
                "mode": man.get("mode"), "operator_statement": man.get("operator_statement"),
                "period": man.get("period"), "hyperparameters": man.get("hyperparameters"),
                "levels": levels, "threat_mode": pipe.threat_mode,
                "domain_assumption": man.get("domain_assumption")}  # fmt: skip

    @app.get("/incidents")
    def incidents(
        status: Annotated[list[str] | None, Query()] = None,
        severity: Annotated[list[str] | None, Query()] = None,
        level: str | None = Query(None, pattern="^(global|device|service)$"),
        entity: str | None = Query(None, max_length=256),
        source: str | None = Query(None, max_length=256),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict:
        """Incidents (grouped anomalous windows of one entity), most recent activity first."""
        try:
            items, total = store.incidents(status, severity, level, entity, source, since,
                                           until, limit, offset)  # fmt: skip
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"items": items, "total": total, "limit": limit, "offset": offset,
                "next_offset": offset + limit if offset + limit < total else None}  # fmt: skip

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: str) -> dict:
        found = store.get_incident(incident_id)
        if not found:
            raise HTTPException(404, "incident not found")
        return found

    @app.post("/incidents/{incident_id}/status", dependencies=[Depends(admin)])
    def incident_status(incident_id: str, req: IncidentStatusRequest) -> dict:
        try:
            return store.set_incident_status(incident_id, req.status, req.note, by="api")
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    def pipeline():
        engine()  # raises 503 when the bundle is missing
        return state["pipeline"]

    def _assess_records(frame, source: str, context: str) -> list[Prediction]:
        """Flow records (CICFlowMeter-style, no endpoints) cannot be windowed into behaviour,
        so behaviour is `not_calibrated`; the supervised threat policy still applies."""
        from netsentinel.inference.pipeline import decide_verdict, threat_status_for

        pipe = pipeline()
        out = []
        for p in engine().predict(frame, source=source, context=context):
            ts = threat_status_for(pipe.threat_mode, p.threat)
            v = decide_verdict(ts, "not_calibrated", bool(p.anomaly and p.anomaly.is_anomalous))
            out.append(p.model_copy(update={"threat_status": ts, "verdict": v}))
        return out

    @app.post("/predict/flow", response_model=Prediction)
    def predict_flow(flow: FlowRecord) -> Prediction:
        # Single flows carry no traffic history -> context features are reported as missing.
        return _assess_records(_flows_to_frame([flow]), flow.source, "none")[0]

    @app.post("/predict/batch", response_model=list[Prediction])
    def predict_batch(req: BatchRequest, compute_context: bool = False) -> list[Prediction]:
        """`compute_context=true` treats the batch as one contiguous stream (causal context)."""
        frame = _flows_to_frame(req.flows)
        return _assess_records(frame, req.flows[0].source,
                               "compute" if compute_context else "none")  # fmt: skip

    @app.get("/events")
    def events(
        verdict: Annotated[list[str] | None, Query()] = None,
        since: datetime | None = None,
        until: datetime | None = None,
        source: str | None = None,
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> list[dict]:
        try:
            return store.query(verdict, since, until, source, limit, offset)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/events/{observation_id}")
    def event(observation_id: str) -> dict:
        found = store.get(observation_id)
        if not found:
            raise HTTPException(404, "event not found")
        return found

    @app.get("/metrics/summary")
    def summary(source: str | None = None) -> dict:
        return store.summary(source)

    @app.post("/replay/start", dependencies=[Depends(admin)])
    def replay_start(req: ReplayRequest) -> dict:
        if replayer is None:
            raise HTTPException(503, "model bundle not loaded")
        path = (settings.replay_dir / f"{req.day}.parquet").resolve()
        if settings.replay_dir.resolve() not in path.parents or not path.is_file():
            raise HTTPException(404, f"no ingested day {req.day}")
        try:
            st = replayer.start_background(ReplayConfig(
                path=str(path), start=req.start, end=req.end, max_events=req.max_events,
                speed=req.speed,
            ))  # fmt: skip
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc
        return st.as_dict()

    @app.post("/analyze", dependencies=[Depends(admin)])
    async def analyze(file: UploadFile, utc_offset: float = Query(0.0, ge=-14, le=14)) -> dict:
        """Offline analysis of one uploaded capture (PCAP/pcapng or Zeek conn.log)."""
        import tempfile

        from netsentinel.streaming.offline import analyze_capture

        if state["engine"] is None:
            raise HTTPException(503, "model bundle not loaded")
        tmp = Path(tempfile.mkdtemp(prefix="netsentinel-upload-")) / "capture.bin"
        size = 0
        try:
            with tmp.open("wb") as fh:
                while chunk := await file.read(1 << 20):
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(
                            413, f"upload exceeds {settings.max_upload_bytes} bytes"
                        )
                    fh.write(chunk)
            name = os.path.basename(file.filename or "upload")[:128]
            try:
                return analyze_capture(
                    tmp, settings.bundle_dir, settings.events_db, utc_offset, source_name=name,
                    calibration_dir=settings.calibration_dir, appid_dir=settings.appid_dir,
                    threat_policy=settings.threat_policy)  # fmt: skip
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
        finally:
            tmp.unlink(missing_ok=True)
            tmp.parent.rmdir()

    @app.post("/replay/cancel", dependencies=[Depends(admin)])
    def replay_cancel() -> dict:
        if replayer:
            replayer.cancel()
        return {"status": "cancel requested"}

    @app.get("/replay/status")
    def replay_status() -> dict:
        return replayer.status.as_dict() if replayer else {"state": "unavailable"}

    return app
