"""Phase 8e M6: backward compatibility of the uncertainty-state changes with the artifacts that
already exist locally:
* every model bundle still loads; behaviour calibrations either load or are refused with the
  explicit "recalibrate" error (calibration schema policy since Phase 7);
* every event store migrates (copied first; the originals are never opened for writing), keeps
  its row count, and its old payloads still validate against the Prediction schema;
* a calibration made with the current code analyzes its own capture end to end (an in-sample
  engineering check, not a detection claim).
Usage: uv run python scripts/phase8e/compat_check.py
"""

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from netsentinel.inference.engine import Engine
from netsentinel.inference.pipeline import AnalysisPipeline
from netsentinel.inference.schema import Prediction
from netsentinel.resources import peak_rss_mb
from netsentinel.storage.events import EventStore
from netsentinel.streaming.offline import analyze_capture

OUT = Path("reports/phase8e/compat_check.json")
res: dict = {"bundles": {}, "calibrations": {}, "event_stores": {}}

for b in sorted(Path("models").glob("bundle-*")):
    e = Engine(b)
    res["bundles"][b.name] = {"loads": True, "bundle_id": e.bundle_id}

for c in sorted(Path("models/calibrations").glob("calibration-*")):
    mf = json.loads((c / "manifest.json").read_text("utf-8"))
    bundle = Path("models") / mf["threat_model_domain_check"]["bundle"]
    try:
        pipe = AnalysisPipeline(bundle, c)
    except ValueError as exc:
        res["calibrations"][c.name] = {"loads": False, "schema": mf.get("schema_version"),
                                       "refused_with": str(exc)}  # fmt: skip
        continue
    ctx = pipe.assessment_context("ok")
    res["calibrations"][c.name] = {
        "loads": True, "bundle": bundle.name, "status": pipe.profile.status,
        "threat_mode": pipe.threat_mode, "threshold_reliable": ctx.threshold_reliable,
        "tail_dominated": ctx.tail_dominated, "calibration_end_ms": ctx.calibration_end_ms,
    }  # fmt: skip

with tempfile.TemporaryDirectory(prefix="ns-compat-", ignore_cleanup_errors=True) as tmp:
    for db in sorted(Path("artifacts").glob("*.sqlite")):
        copy = Path(tmp) / db.name
        shutil.copy2(db, copy)
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            had = "assessment_state" in {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        store = EventStore(copy)
        s = store.summary()
        sample = store.query(limit=200)
        bad = 0
        for ev in sample:
            try:
                Prediction.model_validate(ev)
            except Exception:  # noqa: BLE001 - counted, reported
                bad += 1
        res["event_stores"][db.name] = {
            "rows_before": before, "rows_after": sum(s["counts"].values()),
            "had_assessment_column": had, "assessment_states": s["assessment_states"],
            "payloads_checked": len(sample), "payloads_failing_schema": bad,
        }  # fmt: skip
        store.close()

    from netsentinel.cli import main

    pcap = "data/raw/ctu_normal_26/2017-04-28_normal.pcap"
    bundle = Path("models/bundle-20261019T202605Z")  # the bundle of the Phase 6 calibrations
    assert main(["calibrate", pcap, "--mode", "vetted_benign", "--assert-benign", "--bundle",
                 str(bundle), "--out", str(Path(tmp) / "cal")]) == 0  # fmt: skip
    cal = next((Path(tmp) / "cal").glob("calibration-*"))
    s = analyze_capture(pcap, bundle, Path(tmp) / "ev.sqlite", calibration_dir=cal)
    res["current_calibration_end_to_end"] = {
        "role": "in-sample engineering check (the calibration capture itself); not a claim",
        "calibration": cal.name,
        **{k: s.get(k) for k in ("flows", "verdicts", "telemetry_health", "assessment_states",
                                 "normality_supported_share", "baseline_state")},
    }  # fmt: skip

res["peak_rss_mb"] = peak_rss_mb()
OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
print(json.dumps(res, indent=1, default=str))
