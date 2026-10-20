"""Evidence-aware analysis: supervised threat model + local behaviour profile + application
intelligence, combined without letting one stand in for another.

Supervised-threat policy (Phase 7, safe default):
  unverified  (DEFAULT) the network is not known to resemble the supervised model's training
              data -> threat_status `unverified_domain`; scores are reported, verdicts are
              never escalated by the supervised model.
  auto        escalate only if the calibration's domain check (version >= 2: enough flows and
              a flag rate statistically compatible with the validation FPR) passed for THIS
              bundle; otherwise `unverified_domain` / `unsupported_domain`.
  trust       operator assertion that the traffic is in the training domain (e.g. replaying
              the training dataset); verdicts are escalated.
  unsupported never escalate (`unsupported_domain`).
Phase 6 used `auto` with a lenient check by default; on an unfamiliar CTU capture the check
passed and produced false `suspicious` verdicts (docs/phase7/RELIABILITY.md).

Decision (`decide_verdict`, per flow; first matching rule wins):
  attack            threat_status == known_attack_category
  suspicious        threat_status == suspicious
  unusual           behaviour anomalous (calibrated) - or, uncalibrated, the legacy bundle
                    anomaly flag (documented as unreliable on new networks)
  insufficient_data behaviour insufficient_history; or no calibration AND no assessed
                    supervised model (normality cannot be claimed)
  benign            otherwise
An anomaly alone is never `suspicious`.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl

from netsentinel.inference.engine import Engine
from netsentinel.inference.schema import ApplicationOut, BehaviorOut, Prediction
from netsentinel.models.service import service_category_expr

THREAT_POLICIES = ("unverified", "auto", "trust", "unsupported")
DEFAULT_THREAT_POLICY = "unverified"
ASSESSED = "assessed"
LEVEL_ORDER = ("device", "service", "global")  # most specific first


def threat_mode_for(policy: str, bundle_id: str | None, check: dict | None) -> str:
    """Resolve the supervised-threat mode from the policy and the calibration domain check."""
    if policy not in THREAT_POLICIES:
        raise ValueError(f"threat_policy must be one of {THREAT_POLICIES}")
    if bundle_id is None:
        return "not_assessed"
    if policy == "trust":
        return ASSESSED
    if policy == "unsupported":
        return "unsupported_domain"
    if policy == "auto" and check and check.get("bundle") == bundle_id:
        if int(check.get("version", 1)) >= 2 and check.get("supported") is True:
            return ASSESSED
        if check.get("supported") is False and check.get("reason") != "insufficient_flows":
            return "unsupported_domain"
    return "unverified_domain"


def threat_status_for(mode: str, threat) -> str:
    if mode != ASSESSED:
        return mode
    if threat is None:
        return "not_assessed"
    if threat.is_suspicious:
        return "known_attack_category" if threat.attack_category not in (None, "unknown") else (
            "suspicious")  # fmt: skip
    return "no_evidence"


def decide_verdict(threat_status: str, behavior_status: str, legacy_anomalous: bool) -> str:
    if threat_status == "known_attack_category":
        return "attack"
    if threat_status == "suspicious":
        return "suspicious"
    if behavior_status == "anomalous" or (behavior_status == "not_calibrated" and legacy_anomalous):
        return "unusual"
    if behavior_status == "insufficient_history":
        return "insufficient_data"
    if behavior_status == "not_calibrated" and threat_status != "no_evidence":
        return "insufficient_data"  # neither a baseline nor a trusted model: no normality claim
    return "benign"


def _utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, UTC).replace(tzinfo=None)


class AnalysisPipeline:
    def __init__(self, bundle_dir: str | Path | None, calibration_dir: str | Path | None = None,
                 appid_dir: str | Path | None = None,
                 threat_policy: str = DEFAULT_THREAT_POLICY,
                 engine: Engine | None = None):  # fmt: skip
        if threat_policy not in THREAT_POLICIES:
            raise ValueError(f"threat_policy must be one of {THREAT_POLICIES}")
        self.engine = engine or (Engine(bundle_dir) if bundle_dir else None)
        self.profile = self.calibration = None
        if calibration_dir:
            from netsentinel.behavior.calibrate import load_profile

            self.profile, self.calibration = load_profile(calibration_dir)
        self.classifier = self.classifier_manifest = None
        if appid_dir:
            from netsentinel.appintel.model import load_classifier

            self.classifier, self.classifier_manifest = load_classifier(appid_dir)
        check = (self.calibration or {}).get("threat_model_domain_check") or {}
        self.threat_mode = threat_mode_for(threat_policy, self.engine.bundle_id if self.engine
                                           else None, check)  # fmt: skip
        self.threat_policy = threat_policy

    def versions(self) -> dict[str, str]:
        v = dict(self.engine.model_versions) if self.engine else {}
        if self.calibration:
            v["calibration"] = self.calibration["calibration_id"]
        if self.classifier_manifest:
            v["appid"] = self.classifier_manifest["classifier_id"]
        return v

    # ------------------------------------------------------------------ components
    def _application(self, frame: pl.DataFrame) -> list[ApplicationOut]:
        svc = frame.select(service_category_expr())["service"].to_list()
        proto = frame["protocol"].cast(pl.Int64).to_list()
        if self.classifier is None:
            from netsentinel.appintel.model import TRANSPORT

            return [ApplicationOut(transport=TRANSPORT.get(p, "other"), service_category=s)
                    for p, s in zip(proto, svc, strict=True)]  # fmt: skip
        app = self.classifier.predict(frame)
        cid = self.classifier_manifest["classifier_id"]
        return [ApplicationOut(transport=r["transport"], app_protocol=r["app_protocol"],
                               app_status=r["app_status"],
                               app_confidence=float(np.clip(r["app_confidence"], 0, 1)),
                               service_category=s, classifier=cid)
                for r, s in zip(app.iter_rows(named=True), svc, strict=True)]  # fmt: skip

    def _behavior(self, frame: pl.DataFrame) -> tuple[list[BehaviorOut], pl.DataFrame]:
        if self.profile is None:
            return [BehaviorOut(behavior_status="not_calibrated",
                                baseline_status="no_calibration_loaded")] * frame.height, (
                pl.DataFrame())  # fmt: skip
        from netsentinel.behavior.monitor import baseline_state, score_flows

        cid = self.calibration["calibration_id"]
        if self.profile.status != "baseline_ready":
            b = BehaviorOut(
                behavior_status="insufficient_history",
                baseline_status=self.profile.status,
                calibration=cid,
                explanation=[self.profile.diagnostics.get("cold_start") or ""],
            )
            return [b] * frame.height, pl.DataFrame()
        scored = score_flows(self.profile, frame)
        state = baseline_state(self.profile, scored)["state"]
        w_ms = self.profile.window_s * 1000
        # window keys computed in the frame's own row order (prepare_flows re-sorts)
        end = (frame["flow_end_milliseconds"].cast(pl.Int64) // w_ms).to_numpy()
        keys = {"global": np.full(frame.height, "*", dtype=object),
                "device": frame["ipv4_src_addr"].cast(pl.Utf8).to_numpy().astype(object),
                "service": frame.select(service_category_expr())["service"].to_numpy()}  # fmt: skip
        lookup: dict[str, dict] = {}
        for lv in LEVEL_ORDER:
            d = scored.filter(pl.col("level") == lv)
            pairs = zip(
                d["key"].to_list(), d["win"].to_list(), d.iter_rows(named=True), strict=True
            )
            lookup[lv] = {(k, w): r for k, w, r in pairs}
        out = []
        for i in range(frame.height):
            rows = {lv: lookup[lv].get((keys[lv][i], int(end[i]))) for lv in LEVEL_ORDER}
            hit = next((lv for lv in LEVEL_ORDER if rows[lv] and rows[lv]["anomalous"]), None)
            r = rows[hit] if hit else next((rows[lv] for lv in LEVEL_ORDER if rows[lv]), None)
            if r is None:
                out.append(BehaviorOut(behavior_status="insufficient_history",
                                       baseline_status=state, calibration=cid))  # fmt: skip
                continue
            sev = r["severity"]
            out.append(BehaviorOut(
                behavior_status="anomalous" if hit else "normal",
                anomaly_score=None if sev is None or np.isnan(sev) else float(min(sev, 100.0)),
                raw_score=float(r["score"]), threshold=float(r["threshold"]),
                model_scope=f"{r['level']}:{r['model_scope']}", window_s=self.profile.window_s,
                window_end=_utc(r["window_end_ms"]), baseline_status=state, calibration=cid,
                explanation=list(r["explanation"] or [])))  # fmt: skip
        return out, scored

    # ------------------------------------------------------------------ main entry
    def assess(self, frame: pl.DataFrame, source: str,
               context: str = "compute") -> tuple[list[Prediction], pl.DataFrame]:  # fmt: skip
        if self.engine is None:
            raise ValueError("a model bundle is required for flow assessment")
        preds = self.engine.predict(frame, source=source, context=context)
        apps = self._application(frame)
        behs, windows = self._behavior(frame)
        out = []
        for p, a, b in zip(preds, apps, behs, strict=True):
            ts = threat_status_for(self.threat_mode, p.threat)
            verdict = decide_verdict(ts, b.behavior_status,
                                     bool(p.anomaly and p.anomaly.is_anomalous))  # fmt: skip
            out.append(p.model_copy(update={"application": a, "behavior": b,
                                             "threat_status": ts, "verdict": verdict,
                                             "model_versions": self.versions()}))  # fmt: skip
        return out, windows

    def summary(self, preds: list[Prediction], windows: pl.DataFrame) -> dict[str, Any]:
        s: dict[str, Any] = {
            "verdicts": dict(Counter(p.verdict for p in preds)),
            "threat_status": dict(Counter(p.threat_status for p in preds)),
            "threat_mode": self.threat_mode,
            "threat_policy": self.threat_policy,
            "behavior_status": dict(Counter(p.behavior.behavior_status for p in preds
                                            if p.behavior)),
            "app_status": dict(Counter(p.application.app_status for p in preds
                                       if p.application)),
            "app_protocols": dict(Counter(p.application.app_protocol for p in preds
                                          if p.application and p.application.app_protocol)),
            "service_categories": dict(Counter(p.application.service_category for p in preds
                                               if p.application)),
            "model_versions": self.versions(),
        }  # fmt: skip
        if windows.height:
            from netsentinel.behavior.monitor import baseline_state

            s["behavior_windows"] = {
                lv: {"windows": int(d.height), "anomalous": int(d["anomalous"].sum())}
                for (lv,), d in windows.group_by("level")}  # fmt: skip
            s["baseline_state"] = baseline_state(self.profile, windows)
        return s
