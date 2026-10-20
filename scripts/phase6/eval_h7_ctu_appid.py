"""Phase 6, H7: does selective prediction improve application identification under
distribution shift?

Data: CTU-Normal-20..32 + CTU-Normal-26 Zeek conn logs (never used for any model choice).
Reference: Zeek's own `service` field (Zeek protocol analyzers - independent of nDPI) for
dns -> dns, ssl -> tls, http -> http; flows without one of these services are excluded.
Classifier: an AppClassifier artifact trained on NF-CICIDS2018 (different network, nDPI proxy
labels). Zeek provides only the portable fields, so a `portable`-feature classifier is needed.
Comparators: accuracy of the top class with no abstention; a port rule (53->dns, 443->tls,
80->http, else wrong).
H7 supported if pooled accepted accuracy - pooled no-abstention accuracy >= 0.05 at pooled
coverage >= 0.5.

Usage: uv run python scripts/phase6/eval_h7_ctu_appid.py models/appintel/<artifact>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.appintel.model import load_classifier
from netsentinel.streaming.offline import load_capture

SVC = {"dns": 1.0, "ssl": 2.0, "http": 3.0}
REF = {1.0: "dns", 2.0: "tls", 3.0: "http"}
PORT_RULE = {53: "dns", 443: "tls", 80: "http"}


def svc_code(d: dict) -> float:
    s = str(d.get("service", "-")).split(",")[0]
    return SVC.get(s, 0.0)


def main() -> None:
    clf, manifest = load_classifier(sys.argv[1])
    caps = [Path("data/raw/ctu_normal_26/bro/conn.log"),
            *sorted(Path("data/raw/ctu_normal").glob("CTU-Normal-*/conn.log"))]  # fmt: skip
    rows, pooled = [], {"n": 0, "ok_all": 0, "acc": 0, "ok_acc": 0, "ok_port": 0}
    for cap in caps:
        name = cap.parent.name if cap.parent.name != "bro" else "CTU-Normal-26"
        frame, _, _ = load_capture(cap, "zeek", zeek_extras={"ZEEK_SERVICE": svc_code})
        frame = frame.filter(pl.col("zeek_service") > 0)
        if not frame.height:
            continue
        p = clf.predict(frame)
        ref = np.array([REF[v] for v in frame["zeek_service"].to_list()], dtype=object)
        top = np.array(p["app_top_class"].to_list(), dtype=object)
        acc_mask = np.array([s == "predicted" for s in p["app_status"].to_list()])
        final = np.array(p["app_protocol"].to_list(), dtype=object)  # after any policy
        port = np.array([PORT_RULE.get(int(x)) for x in frame["dst_port"].to_list()], dtype=object)
        ok_all, ok_port = top == ref, port == ref
        r = {"capture": name, "flows": frame.height,
             "ref_mix": {k: int((ref == k).sum()) for k in ("dns", "tls", "http")},
             "accuracy_no_abstention": float(ok_all.mean()),
             "coverage": float(acc_mask.mean()),
             "accepted_accuracy": float(ok_all[acc_mask].mean()) if acc_mask.any() else None,
             "port_rule_accuracy": float(ok_port.mean()),
             "final_label_accepted_accuracy": float((final == ref)[acc_mask].mean())
             if acc_mask.any() else None,
             "methods": {str(k): int(v) for k, v in zip(*np.unique(
                 [str(m) for m in p["app_method"].to_list()], return_counts=True), strict=True)}
             if "app_method" in p.columns else None,
             "status": dict(zip(*np.unique(p["app_status"].to_list(), return_counts=True),
                                strict=True)),
             "per_ref_recall": {k: float(ok_all[ref == k].mean()) for k in ("dns", "tls", "http")
                                if (ref == k).any()}}  # fmt: skip
        r["status"] = {k: int(v) for k, v in r["status"].items()}
        rows.append(r)
        pooled["n"] += frame.height
        pooled["ok_all"] += int(ok_all.sum())
        pooled["acc"] += int(acc_mask.sum())
        pooled["ok_acc"] += int(ok_all[acc_mask].sum())
        pooled["ok_final"] = pooled.get("ok_final", 0) + int((final == ref)[acc_mask].sum())
        pooled["ok_port"] += int(ok_port.sum())
        print(name, {k: v for k, v in r.items() if k not in ("status",)}, flush=True)
    acc_all = pooled["ok_all"] / pooled["n"]
    cov = pooled["acc"] / pooled["n"]
    acc_sel = pooled["ok_acc"] / pooled["acc"] if pooled["acc"] else None
    summary = {"classifier": manifest["classifier_id"], "feature_set": manifest["feature_set"],
               "pooled_flows": pooled["n"], "accuracy_no_abstention": acc_all,
               "coverage": cov, "accepted_accuracy": acc_sel,
               "port_rule_accuracy": pooled["ok_port"] / pooled["n"],
               "final_label_accepted_accuracy": pooled.get("ok_final", 0) / pooled["acc"]
               if pooled["acc"] else None,
               "H7_supported": bool(acc_sel is not None and cov >= 0.5
                                    and acc_sel - acc_all >= 0.05)}  # fmt: skip
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "reports/phase6/h7_ctu_appid.json")
    out.write_text(json.dumps({"captures": rows, "summary": summary}, indent=1, default=str),
                   "utf-8")  # fmt: skip
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
