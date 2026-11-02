"""Phase 8l label-integrity audit of the F1 (AIT Netflow v2) probe network `russellmitchell`.

The probe is excluded from confirmation by registration (docs/phase8k/PREREGISTRATION.md
section 2) and was opened under authorization in Phase 8k, so its full labels may be audited
here. The other 7 AIT networks are NOT read. Nothing is relabelled: this measures how the
published per-flow labels (AIT notebook `2_label_logs.ipynb`: time-window attack labels, rule-based
benign labels, defaults) relate to the published host roles (`role_cli` / `role_serv`).

Reports: role vocabulary and source hosts per role; the label mix of flows sent by the attacker
role and by non-attacker roles; how many non-attacker hosts carry attack-step labels (the
time-window rule labels every unmatched flow in a step's window, whatever its host); the attack
timeline relative to the time midpoint; and the effective number of benign source hosts.

Output: reports/phase8l/label_audit_f1.json
Usage: uv run python scripts/run_capped.py -- <python> -I scripts/phase8l/label_audit_f1.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "phase8k"))
import telemetry_maps as TM  # noqa: E402, N812

DIR = ROOT / "data" / "raw" / "phase8k_probes" / "ait" / "extracted"
OUT = ROOT / "reports" / "phase8l" / "label_audit_f1.json"
STEP_LABELS = TM.AIT_MALICIOUS - {"data exfiltration"}


def load() -> pl.DataFrame:
    parts = []
    for name, ts, cip, sip in (("tcp_complete", "first", "c_ip", "s_ip"),
                               ("tcp_nocomplete", "first", "c_ip", "s_ip"),
                               ("udp_complete", "c_first_abs", "c_ip", "s_ip")):  # fmt: skip
        p = DIR / f"{name}.csv"
        cols = TM.tstat_columns(p)
        df = pl.read_csv(p, has_header=False, skip_rows=1, new_columns=cols, infer_schema_length=0,
                         columns=[cols.index(c) for c in (ts, cip, sip, "role_cli", "role_serv",
                                                           "network_cli", "label")])  # fmt: skip
        parts.append(df.rename({ts: "t", cip: "src", sip: "dst"}).with_columns(
            pl.col("t").cast(pl.Float64), pl.lit(name).alias("file")))  # fmt: skip
    return pl.concat(parts).sort("t")


def main() -> None:
    f = load()
    lo, hi = f["t"].min(), f["t"].max()
    mid = lo + (hi - lo) / 2
    is_step = pl.col("label").is_in(sorted(STEP_LABELS))
    is_mal = pl.col("label").is_in(sorted(TM.AIT_MALICIOUS))
    att_role = pl.col("role_cli").str.starts_with("attacker")
    res = {"flows": f.height, "span_hours": (hi - lo) / 3.6e6,
           "roles_cli": dict(f.group_by("role_cli").agg(pl.col("src").n_unique()).sort("role_cli").iter_rows()),
           "attacker_hosts": sorted(f.filter(att_role)["src"].unique().to_list()),
           "attacker_as_client_labels": dict(f.filter(att_role).group_by("label").len().sort("len", descending=True).iter_rows()),
           "attacker_as_server_labels": dict(f.filter(pl.col("role_serv").str.starts_with("attacker"))
                                             .group_by("label").len().sort("len", descending=True).iter_rows()),
           "step_labelled_flows": int(f.filter(is_step).height),
           "step_labelled_flows_from_non_attacker_roles": int(f.filter(is_step & ~att_role).height),
           "non_attacker_hosts_with_step_labels": int(f.filter(is_step & ~att_role)["src"].n_unique()),
           "non_attacker_roles_with_step_labels": dict(f.filter(is_step & ~att_role).group_by("role_cli")
                                                       .agg(pl.col("src").n_unique().alias("hosts"), pl.len().alias("flows"))
                                                       .sort("flows", descending=True).select("role_cli", "flows").iter_rows()),
           "malicious_source_hosts": int(f.filter(is_mal)["src"].n_unique()),
           "malicious_flows_before_midpoint": int(f.filter(is_mal & (pl.col("t") < mid)).height),
           "malicious_flows_after_midpoint": int(f.filter(is_mal & (pl.col("t") >= mid)).height),
           "step_flows_before_midpoint": int(f.filter(is_step & (pl.col("t") < mid)).height),
           "attack_step_first_last_hours": {k: [round((a - lo) / 3.6e6, 2), round((b - lo) / 3.6e6, 2)]
                                            for k, a, b in f.filter(is_step).group_by("label")
                                            .agg(pl.col("t").min().alias("a"), pl.col("t").max().alias("b")).sort("a").iter_rows()},
           "hourly_flows_min_median_max": None}  # fmt: skip
    hours = np.bincount(((f["t"].to_numpy() - lo) // 3.6e6).astype(int))
    res["hourly_flows_min_median_max"] = [
        int(hours.min()),
        float(np.median(hours)),
        int(hours.max()),
    ]
    # host diversity of senders that never carry a malicious label, over the whole capture
    mal_src = set(f.filter(is_mal)["src"].unique().to_list())
    ben = f.filter(~pl.col("src").is_in(sorted(mal_src)))
    m = ben.group_by("src").len()["len"].to_numpy().astype(float)
    res["never_malicious_sources"] = len(m)
    res["never_malicious_effective_sources_by_flows"] = float(m.sum() ** 2 / (m**2).sum())
    res["never_malicious_top5_flow_share"] = float(np.sort(m)[-5:].sum() / m.sum())
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=1, default=str), "utf-8")
    print(json.dumps(res, indent=1, default=str)[:6000])


if __name__ == "__main__":
    main()
