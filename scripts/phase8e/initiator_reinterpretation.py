"""Phase 8e, Mission 1 (RETROSPECTIVE REINTERPRETATION; the frozen Phase 8c verdicts and their
reported numbers are NOT changed).

The label audit (label_provenance.py) shows that in ToN_IoT files 1-4 every attack-labelled flow
has one of three scanners (192.168.1.30/.31/.32) as an endpoint; the other 37 "attack-labelled
sources" only send responses TO the scanners. The frozen "attackers detected (n/40)" therefore
counted attack-INVOLVED sources. This script recomputes, for the frozen policies A, C2 and E
(identical windows, scores and alerts as the frozen run), detection separated by role:
* initiators (the 3 scanners);
* responders (sources whose attack-labelled flows all go to a scanner).
Usage: uv run --extra torch python scripts/phase8e/initiator_reinterpretation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "phase8c"))
sys.path.insert(0, str(HERE.parents[0] / "phase8b"))
import scorers as S  # noqa: E402, N812
from confirm_external import EXCLUDED_FROM_TRAINING  # noqa: E402
from dev_compare import dev_captures  # noqa: E402
from harness import load, with_truth  # noqa: E402
from policies import lgbm_policy, robust_policies  # noqa: E402

TON = Path("data/derived/phase8c_external/toniot")
OUT = Path("reports/phase8e/initiator_reinterpretation.json")
INITIATORS = ["192.168.1.30", "192.168.1.31", "192.168.1.32"]


def main() -> None:
    names = [n for n in dev_captures() if n not in EXCLUDED_FROM_TRAINING
             and (Path("data/derived/phase8b") / n / "meta.json").exists()]  # fmt: skip
    srcs = []
    for n in names:
        dd = load(Path("data/derived/phase8b") / n)
        if dd["cal_clean"].height:
            srcs.append({"cal": dd["cal_clean"], "ev": dd["eval_clean"], "truth": dd["truth"]})
    model, src_thr = S.lgbm_fit(srcs, False)
    d = load(TON)
    cal, ev = d["cal_clean"], d["eval_clean"]
    e = with_truth(ev.select("key", "win", "window_end_ms"), d["truth"])
    y = e["y"].to_numpy()
    keys = np.array(e["key"].to_list(), dtype=object)
    rp = robust_policies(cal, ev)
    se = model.predict_proba(S._x(ev))[:, 1]
    pol = {"A": rp["A"][1], "C2": rp["C2"][1], "E": lgbm_policy(model, cal, ev)[1],
           "E_source_threshold": se > src_thr}  # fmt: skip
    involved = sorted(set(keys[y]))
    responders = [k for k in involved if k not in INITIATORS]
    res = {"role": "retrospective reinterpretation; frozen X1-X5 unchanged",
           "attack_involved_sources": len(involved), "initiators": INITIATORS,
           "responders": len(responders), "policies": {}}  # fmt: skip
    for p, alert in pol.items():
        init = {k: {"attack_windows": int(((keys == k) & y).sum()),
                    "alerted_attack_windows": int(((keys == k) & y & alert).sum())}
                for k in INITIATORS}  # fmt: skip
        resp_det = sum(bool(((keys == k) & y & alert).any()) for k in responders)
        mi = np.isin(keys, INITIATORS) & y
        mr = np.isin(keys, responders) & y
        res["policies"][p] = {
            "initiators_detected": f"{sum(v['alerted_attack_windows'] > 0 for v in init.values())}/3",
            "initiator_window_recall": float(alert[mi].mean()) if mi.any() else None,
            "responders_alerted": f"{resp_det}/{len(responders)}",
            "responder_window_alert_rate": float(alert[mr].mean()) if mr.any() else None,
            "fpr_benign_windows": float(alert[~y].mean()),
            "per_initiator": init}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1), "utf-8")
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
