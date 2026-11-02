"""Phase 8l DEDALE source models (docs/phase8l/DEDALE_PREREGISTRATION.md section 3, step 4).

The registered Phase 8i B-raw LightGBM (`common.fit_source`, Phase 8i settings, `Rep("raw")`)
fitted once per seed on every domain of the four NF-v3 development networks (nfcic, nfunsw,
nfton, nfbot), as in Phase 8k. No DEDALE data is read. Each model is saved as a LightGBM text
file, reloaded, and checked to reproduce `predict_proba` on a source hold-out; its SHA-256 goes
into the report for DEDALE_FREEZE.md.

Output: data/derived/phase8l/dedale/models/b_raw_seed<k>.txt and
reports/phase8l/dedale_source_models.json
Usage (from the repository root):
  uv run python scripts/run_capped.py -- <abs python> scripts/phase8l/dedale_source_models.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "data" / "derived" / "phase8l" / "dedale" / "models"
OUT = ROOT / "reports" / "phase8l" / "dedale_source_models.json"
NETWORKS = ("nfcic", "nfunsw", "nfton", "nfbot")
SEEDS = (0, 1, 2)


def _common():
    spec = importlib.util.spec_from_file_location("common_8i", ROOT / "scripts/phase8i/common.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["common_8i"] = mod
    spec.loader.exec_module(mod)
    return mod


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    import lightgbm as lgb

    from netsentinel.resources import peak_rss_mb

    t0 = time.perf_counter()
    c = _common()
    sources = {name: d for n in NETWORKS for name, d in c.load_network(n).items()}
    MODELS.mkdir(parents=True, exist_ok=True)
    check = next(iter(sources.values()))
    x_check = c.S._x(c.prepare(check)["_hold"])
    rep = {
        "git_sha": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                  capture_output=True, text=True).stdout.strip(),
        "lightgbm": lgb.__version__, "settings": c.LGB, "representation": "raw",
        "features": list(c.S.FEATS), "source_domains": sorted(sources), "models": {},
    }  # fmt: skip
    for seed in SEEDS:
        m, thr, n = c.fit_source(sources, seed, c.Rep("raw"))
        path = MODELS / f"b_raw_seed{seed}.txt"
        m.booster_.save_model(str(path))
        diff = float(np.max(np.abs(lgb.Booster(model_file=str(path)).predict(x_check)
                                   - m.predict_proba(x_check)[:, 1])))  # fmt: skip
        if diff > 1e-9:
            raise SystemExit(f"seed {seed}: reloaded model differs by {diff}")
        rep["models"][str(seed)] = {"file": str(path.relative_to(ROOT)), "sha256": sha256(path),
                                    "train_rows": n, "source_benign_q99": thr,
                                    "reload_max_abs_diff": diff}  # fmt: skip
        print(seed, rep["models"][str(seed)], flush=True)
    rep["peak_rss_mb"] = peak_rss_mb()
    rep["seconds"] = round(time.perf_counter() - t0, 1)
    OUT.write_text(json.dumps(rep, indent=1), "utf-8")


if __name__ == "__main__":
    main()
