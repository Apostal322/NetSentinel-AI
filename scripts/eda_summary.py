"""Print a compact text summary of reports/eda/eda.json (used to write docs/datasets)."""

import json
import sys
from pathlib import Path

eda = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "reports/eda/eda.json").read_text())
for d in eda["days"]:
    print(
        f"{d['day']} rows={d['rows']:>9,} excel_trunc={d['excel_truncated']!s:5} "
        f"ts=[{d['ts_min']} .. {d['ts_max']}] off_day={d['rows_off_day']:,} "
        f"neg_dur={d['negative_duration']:,} ips={d['has_ips']} "
        f"dups={d['duplicates']['duplicate_rows']:,} "
        f"conflicts={d['duplicates']['conflicting_groups']:,}"
    )
    for r in d["labels"]:
        print(
            f"    {r['label']:20s} {r['rows']:>9,}  {r['first'][11:19]}-{r['last'][11:19]} "
            f"port={r['top_dst_port']}({r['top_port_share']:.2f}) proto={r['top_protocol']}"
        )
    nf = {k: v for k, v in d["nonfinite"].items() if not k.startswith("neg::")}
    neg = {k[5:]: v for k, v in d["nonfinite"].items() if k.startswith("neg::")}
    print(f"    nonfinite: {nf}")
    print(f"    negative values: {neg}")
print("constant:", eda["constant_columns"])
print("ip_leakage:", eda["ip_leakage"])
print("top univariate AUC separation:")
for r in eda["univariate_auc"][:15]:
    print(f"    {r['feature']:24s} auc={r['auc']:.3f} sep={r['separation']:.3f}")
