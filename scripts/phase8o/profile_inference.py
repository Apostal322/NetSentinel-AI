"""Phase 8o H2 cost: measured inference cost of K-member ensembles (PREREGISTRATION section 5).

**Members.** The 5 M2 members of the frozen candidate's reference replicate (r = 0, seeds
1000-1004) are refitted on the sources of the NF-CIC target (NF-UNSW + NF-ToN) and saved as
LightGBM text models. Their scores equal the Phase 8n M2 r0 members by construction (R1 checks
the mean).

**What is measured:**
- artifact size and hash;
- in a fresh child process per K (so that peak memory is the scoring process's own):
  import plus load time (cold start), batch scoring throughput with 1 and 2 threads,
  single-window latency (median and p95 over 300 calls) and peak working set, on the NF-CIC
  2018-02-21 P1x evaluation windows;
- feature-building throughput (`prepare_flows` + `aggregate`) on the first Phase 8i slice of that
  day, and the size of its frozen destination memory.

Output: reports/phase8o/inference_profile.json; models in data/derived/phase8o/profile/
Usage: python scripts/run_capped.py -- <python> scripts/phase8o/profile_inference.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "data" / "derived" / "phase8o" / "profile"
EVAL = ROOT / "data" / "derived" / "phase8j" / "p1x" / "nfcic" / "2018-02-21" / "eval_p1x.parquet"
REPORT = ROOT / "reports" / "phase8o" / "inference_profile.json"
KS = (1, 2, 3, 5)


def score_child(k: int) -> dict:
    """Runs in a fresh process: load K members, score the evaluation windows."""
    t_start = time.perf_counter()
    import lightgbm as lgb
    import numpy as np
    import polars as pl

    from netsentinel.behavior.windows import WINDOW_FEATURES
    from netsentinel.resources import peak_rss_mb

    t_import = time.perf_counter()
    boosters = [lgb.Booster(model_file=str(MODELS / f"m{m}.txt")) for m in range(k)]
    t_load = time.perf_counter()
    x = np.nan_to_num(pl.read_parquet(EVAL, columns=list(WINDOW_FEATURES)).select(
        [pl.col(f).cast(pl.Float64) for f in WINDOW_FEATURES]).to_numpy())  # fmt: skip
    out = {"K": k, "windows": int(x.shape[0]), "import_s": t_import - t_start,
           "load_models_s": t_load - t_import}  # fmt: skip
    for threads in (1, 2):
        t = time.perf_counter()
        s = np.mean([b.predict(x, num_threads=threads) for b in boosters], axis=0)
        dt = time.perf_counter() - t
        out[f"batch_s_{threads}t"] = dt
        out[f"windows_per_s_{threads}t"] = x.shape[0] / dt
    lat = []
    for i in range(300):
        row = x[i : i + 1]
        t = time.perf_counter()
        np.mean([b.predict(row, num_threads=1) for b in boosters])
        lat.append(time.perf_counter() - t)
    out["single_window_ms_median"] = float(np.median(lat) * 1000)
    out["single_window_ms_p95"] = float(np.quantile(lat, 0.95) * 1000)
    out["score_checksum"] = float(s.sum())
    out["peak_rss_mb"] = peak_rss_mb()
    return out


def main() -> None:
    import importlib.util

    import numpy as np
    import polars as pl

    spec = importlib.util.spec_from_file_location(
        "phase8o_experiment", ROOT / "scripts/phase8o/experiment_d.py"
    )
    ED = importlib.util.module_from_spec(spec)  # noqa: N806
    sys.modules["phase8o_experiment"] = ED
    spec.loader.exec_module(ED)
    from netsentinel.behavior.windows import aggregate, prepare_flows
    from netsentinel.resources import peak_rss_mb

    t0 = time.perf_counter()
    nets = {n: ED.C.load_network(n) for n in ("nfunsw", "nfton")}
    srcs = {k: v for n in ("nfunsw", "nfton") for k, v in nets[n].items()}
    load_s = time.perf_counter() - t0
    MODELS.mkdir(parents=True, exist_ok=True)
    res: dict = {
        "status": "measurement (no detection result)",
        "members": {},
        "train_load_s": load_s,
    }
    for m in range(5):
        t = time.perf_counter()
        seed = ED.member_seed(0, m)
        clf = ED.CA.fit_one(ED.CA.source_data(srcs, seed, None), seed)
        fit_s = time.perf_counter() - t
        path = MODELS / f"m{m}.txt"
        clf.booster_.save_model(str(path))
        res["members"][m] = {"fit_s": round(fit_s, 2), "bytes": path.stat().st_size,
                             "sha256_16": hashlib.sha256(path.read_bytes()).hexdigest()[:16]}  # fmt: skip
        print("member", m, res["members"][m], flush=True)
    del nets, srcs
    res["train_peak_rss_mb"] = peak_rss_mb()
    # feature building: the first Phase 8i slice of NF-CIC 2018-02-21
    spec = importlib.util.spec_from_file_location(
        "bw_8i", ROOT / "scripts/phase8i/build_windows.py"
    )
    bw = importlib.util.module_from_spec(spec)
    sys.modules["bw_8i"] = bw
    spec.loader.exec_module(bw)
    files = [Path(bw.NETWORKS["nfcic"][0]) / "2018-02-21.parquet"]
    frame = next(bw.chunks(files, True, bw.MAX_ROWS))
    t = time.perf_counter()
    flows = prepare_flows(frame)
    half = int(flows["end_ms"].quantile(0.5))
    known = set(flows.filter(pl.col("end_ms") < half)["dst"].unique().to_list())
    ev = flows.filter(pl.col("end_ms") >= half)
    t_prep = time.perf_counter()
    wins = aggregate(ev, "device", 30, known_dst=known)
    t_agg = time.perf_counter()
    res["features"] = {"flows": flows.height, "eval_flows": ev.height, "windows": wins.height,
                       "prepare_s": t_prep - t, "aggregate_s": t_agg - t_prep,
                       "flows_per_s": ev.height / (t_agg - t_prep),
                       "known_destinations": len(known),
                       "known_set_bytes": sys.getsizeof(known) + sum(sys.getsizeof(d) for d in known)}  # fmt: skip
    del frame, flows, ev, wins
    res["K"] = {}
    for k in KS:
        p = subprocess.run([sys.executable, str(Path(__file__)), "--score", str(k)],
                           capture_output=True, text=True, cwd=ROOT)  # fmt: skip
        if p.returncode:
            raise SystemExit(p.stderr)
        res["K"][k] = json.loads(p.stdout.strip().splitlines()[-1])
        res["K"][k]["artifact_bytes"] = sum(res["members"][m]["bytes"] for m in range(k))
        print("K", k, res["K"][k], flush=True)
    res["seconds"] = round(time.perf_counter() - t0, 1)
    res["numpy"] = np.__version__
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_bytes(json.dumps(res, indent=1).encode())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", type=int)
    a = ap.parse_args()
    if a.score:
        print(json.dumps(score_child(a.score)))
    else:
        main()
