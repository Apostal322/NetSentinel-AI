"""Phase 8d, Mission 1 (POST-HOC sensitivity analysis; the frozen result is NOT replaced).

Rebuilds the ToN_IoT evaluation windows with the CURRENT streaming code (clock resync with
probation) into data/derived/phase8d_posthoc/toniot, and compares them with the windows of the
frozen Phase 8c run (data/derived/phase8c_external/toniot):
* every table (calibration / evaluation windows, clean / unlabelled, truth) cell by cell,
  and the meta (first attack times, flow counts);
* the scores and alerts of the pre-registered policies A, C2 and E computed from both.
Usage: uv run --extra torch python scripts/phase8d/posthoc_windows.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
from confirm_external import EXCLUDED_FROM_TRAINING, build_windows  # noqa: E402
from dev_compare import dev_captures  # noqa: E402
from harness import VARIANTS, load  # noqa: E402
from policies import lgbm_policy, robust_policies  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

FROZEN = Path("data/derived/phase8c_external/toniot")
POSTHOC = Path("data/derived/phase8d_posthoc/toniot")
FILES = [f"data/raw/toniot/Network_dataset_{i}.csv" for i in range(1, 5)]
OUT = Path("reports/phase8d/posthoc_windows.json")


def table_diff(a: pl.DataFrame, b: pl.DataFrame, keys) -> dict:
    a, b = a.sort(keys), b.sort(keys)
    same_shape = a.shape == b.shape and a.columns == b.columns
    out = {"rows": [a.height, b.height], "same_shape": same_shape}
    if same_shape:
        diffs = {}
        for c in a.columns:
            x, y = a[c], b[c]
            if x.dtype.is_numeric():
                xv, yv = x.cast(pl.Float64).to_numpy(), y.cast(pl.Float64).to_numpy()
                both_nan = np.isnan(xv) & np.isnan(yv)
                d = ~both_nan & (xv != yv)
            else:
                d = (x != y).fill_null(x.is_null() != y.is_null()).to_numpy()
            if d.any():
                diffs[c] = int(d.sum())
        out["differing_cells_by_column"] = diffs
        out["identical"] = not diffs
    else:
        out["identical"] = False
    return out


def main() -> None:
    old = load(FROZEN)
    new = load(POSTHOC) if (POSTHOC / "meta.json").exists() else build_windows(FILES, POSTHOC)
    res: dict = {"role": "post-hoc sensitivity analysis; frozen Phase 8c verdicts unchanged",
                 "stream_frozen": old["meta"]["stream"], "stream_current": new["meta"]["stream"],
                 "tables": {}}  # fmt: skip
    for v in VARIANTS:
        for part in ("cal", "eval"):
            k = f"{part}_{v}"
            res["tables"][k] = table_diff(old[k], new[k], ["key", "win"])
    res["tables"]["truth"] = table_diff(old["truth"], new["truth"], ["key", "win"])
    res["meta_equal"] = {k: old["meta"][k] == new["meta"][k]
                         for k in ("flows", "first_attack_ms", "mid_ms", "eval_span_ms")}  # fmt: skip
    # pre-registered policies on both window sets
    names = [n for n in dev_captures() if n not in EXCLUDED_FROM_TRAINING
             and (Path("data/derived/phase8b") / n / "meta.json").exists()]  # fmt: skip
    srcs = []
    for n in names:
        dd = load(Path("data/derived/phase8b") / n)
        if dd["cal_clean"].height:
            srcs.append({"cal": dd["cal_clean"], "ev": dd["eval_clean"], "truth": dd["truth"]})
    model, _ = S.lgbm_fit(srcs, False)
    pol = {}
    for name, d in (("frozen", old), ("current", new)):
        cal, ev = d["cal_clean"].sort("key", "win"), d["eval_clean"].sort("key", "win")
        rp = robust_policies(cal, ev)
        pol[name] = {"A": rp["A"], "C2": rp["C2"], "E": lgbm_policy(model, cal, ev)}
    res["policies"] = {p: {"max_abs_score_diff": float(np.max(np.abs(pol["frozen"][p][0] - pol["current"][p][0]))),
                           "alert_disagreements": int((pol["frozen"][p][1] != pol["current"][p][1]).sum())}
                       for p in ("A", "C2", "E")}  # fmt: skip
    res["peak_rss_mb"] = peak_rss_mb()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps({k: res[k] for k in ("tables", "meta_equal", "policies", "peak_rss_mb")},
                     indent=1, default=str))  # fmt: skip
    print("stream frozen", res["stream_frozen"])
    print("stream current", res["stream_current"])


if __name__ == "__main__":
    main()
