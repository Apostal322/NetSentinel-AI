"""Behaviour windows, profiles and calibration on SYNTHETIC flows (software behaviour only)."""

import json

import numpy as np
import polars as pl
import pytest

from netsentinel.behavior.calibrate import calibrate_flows, load_profile, save_profile
from netsentinel.behavior.monitor import baseline_state, score_flows
from netsentinel.behavior.windows import aggregate, prepare_flows

HOSTS = [f"10.0.0.{i}" for i in range(1, 5)]


def synth(minutes: int, seed: int = 0, start_ms: int = 1_600_000_000_000,
          burst_at_min: int | None = None, burst_host: str = "10.0.0.1") -> pl.DataFrame:  # fmt: skip
    """Steady web/DNS traffic from 4 hosts; optional 1-minute port-scan burst."""
    rng = np.random.default_rng(seed)
    rows = []
    for m in range(minutes):
        for _ in range(rng.poisson(40)):
            h = HOSTS[rng.integers(0, 4)]
            port = int(rng.choice([443, 53, 80], p=[0.6, 0.3, 0.1]))
            t0 = start_ms + m * 60_000 + int(rng.integers(0, 60_000))
            dur = int(rng.integers(1, 3000))
            rows.append((t0, t0 + dur, h, f"93.184.0.{rng.integers(1, 20)}", port,
                         17 if port == 53 else 6, int(rng.integers(100, 5000)),
                         int(rng.integers(200, 50000)), int(rng.integers(2, 20)),
                         int(rng.integers(2, 40)), dur, 0, 0))  # fmt: skip
        if burst_at_min is not None and m == burst_at_min:
            for i in range(600):
                t0 = start_ms + m * 60_000 + i * 100
                rows.append((t0, t0, burst_host, f"172.16.{i // 250}.{i % 250}", 1000 + i, 6,
                             40, 0, 1, 0, 0, 0, 0))  # fmt: skip
    cols = ["flow_start_milliseconds", "flow_end_milliseconds", "ipv4_src_addr",
            "ipv4_dst_addr", "dst_port", "protocol", "in_bytes", "out_bytes", "in_pkts",
            "out_pkts", "flow_duration_milliseconds", "cli_rst", "srv_rst"]  # fmt: skip
    return pl.DataFrame(rows, schema=cols, orient="row")


def test_window_features_are_causal():
    df = synth(60, seed=1)
    flows = prepare_flows(df)
    early = aggregate(flows.filter(pl.col("end_ms") < flows["end_ms"].quantile(0.5)),
                      "device", 30)  # fmt: skip
    full = aggregate(flows, "device", 30)
    last_early = early["win"].max() - 1  # the last COMPLETE window of the early part
    a = early.filter(pl.col("win") <= last_early).sort("key", "win")
    b = full.filter(pl.col("win") <= last_early).sort("key", "win")
    assert a.select("key", "win", "n_flows", "log_up_bytes", "new_dst_frac").equals(
        b.select("key", "win", "n_flows", "log_up_bytes", "new_dst_frac")
    )  # future data unused


def test_flow_assigned_by_end_time_and_silent_windows_kept():
    df = synth(10, seed=2).filter(pl.col("flow_end_milliseconds") < 1_600_000_000_000 + 60_000)
    late = df.head(1).with_columns(pl.lit(1_600_000_000_000 + 400_000).alias(
        "flow_end_milliseconds"))  # fmt: skip
    g = aggregate(prepare_flows(pl.concat([df, late])), "global", 30)
    assert g["n_flows"].sum() == df.height + 1
    assert (g["n_flows"] == 0).sum() > 0  # silence between minute 1 and the late flow
    assert g.filter(pl.col("n_flows") == 0)["log_up_bytes"].null_count() > 0


def test_calibrate_detects_injected_burst_and_ignores_normal():
    cal = synth(240, seed=3)
    prof = calibrate_flows(cal, window_s=30, mode="vetted_benign", target_fpr=0.01)
    assert prof.status == "baseline_ready"
    ev = synth(120, seed=4, start_ms=1_600_000_000_000 + 240 * 60_000, burst_at_min=60)
    s = score_flows(prof, ev)
    dev = s.filter((pl.col("level") == "device") & (pl.col("key") == "10.0.0.1"))
    burst_win = (1_600_000_000_000 + 300 * 60_000) // 30_000
    hit = dev.filter(pl.col("win").is_between(burst_win, burst_win + 1))
    assert hit["anomalous"].any()
    assert any("destination_diversity_above" in e or "unanswered" in e
               for row in hit["explanation"].to_list() for e in row)  # fmt: skip
    normal = s.filter((pl.col("level") == "global") & ~pl.col("win").is_between(
        burst_win - 1, burst_win + 2))  # fmt: skip
    assert normal["anomalous"].mean() <= 0.05
    assert s["severity"].drop_nulls().is_between(0, 100).all()


def test_cold_start_reports_insufficient_history():
    prof = calibrate_flows(synth(5, seed=5), window_s=30, min_windows=30)
    assert prof.status == "insufficient_history" and not prof.levels
    assert "more minutes" in prof.diagnostics["cold_start"]
    s = score_flows(prof, synth(5, seed=6))
    assert s.height == 0
    assert baseline_state(prof, s)["state"] == "collecting_baseline"


def test_unlabelled_trimming_limits_contamination():
    clean = synth(240, seed=7)
    dirty = pl.concat([clean, synth(240, seed=8, burst_at_min=30).filter(
        pl.col("ipv4_dst_addr").str.starts_with("172.16"))])  # fmt: skip
    p_un = calibrate_flows(dirty, mode="unlabelled", target_fpr=0.01)
    assert p_un.levels["device"].trimmed_windows > 0
    assert any("unlabelled" in w for w in p_un.levels["global"].warnings)
    with pytest.raises(ValueError):
        calibrate_flows(clean, mode="nonsense")


def test_artifact_roundtrip_and_tamper_refusal(tmp_path):
    prof = calibrate_flows(synth(120, seed=9), window_s=30)
    out = save_profile(prof, tmp_path, sources=[{"path": "synthetic"}],
                       operator_statement="synthetic test")  # fmt: skip
    loaded, manifest = load_profile(out)
    assert manifest["status"] == "baseline_ready" and loaded.window_s == 30
    mf = json.loads((out / "manifest.json").read_text())
    mf["schema_version"] = "behavior-0.0.1"
    (out / "manifest.json").write_text(json.dumps(mf))
    with pytest.raises(ValueError, match="schema"):
        load_profile(out)
    mf["schema_version"] = manifest["schema_version"]
    (out / "manifest.json").write_text(json.dumps(mf))
    with open(out / "profile.joblib", "ab") as fh:
        fh.write(b"x")
    with pytest.raises(ValueError, match="hash"):
        load_profile(out)
    with pytest.raises(FileNotFoundError):
        load_profile(tmp_path / "nope")


def test_missing_columns_and_empty_input_fail_loudly():
    with pytest.raises(ValueError, match="lacks"):
        prepare_flows(pl.DataFrame({"protocol": [6]}))
    with pytest.raises(ValueError, match="no flows"):
        calibrate_flows(synth(1, seed=1).head(0))


def test_drift_suspected_when_traffic_regime_changes():
    prof = calibrate_flows(synth(240, seed=10), window_s=30, target_fpr=0.01)
    shifted = synth(120, seed=11, start_ms=1_600_000_000_000 + 240 * 60_000).with_columns(
        (pl.col("in_bytes") * 50).alias("in_bytes"), (pl.col("out_bytes") * 50).alias("out_bytes")
    )
    st = baseline_state(prof, score_flows(prof, shifted))
    assert st["state"] == "drift_suspected"
    same = synth(120, seed=12, start_ms=1_600_000_000_000 + 240 * 60_000)
    assert baseline_state(prof, score_flows(prof, same))["state"] == "monitoring"
