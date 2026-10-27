"""Phase 8g step 3 (after the frozen run only): label provenance audit of CTU-13 scenarios 9/10
against the README design (docs/phase8f/PREREG_CTU13.md s.4; LABEL_PROVENANCE.md method).

Refuses to run unless reports/phase8g/results.json exists with status "complete" - the labels
stay blinded until the frozen evaluation has written its outputs. Per label file:
* which file carries a `Label` column (scenario 10 has two candidates);
* label families (From-/To-Botnet, From-/To-Normal, Background, C&C, other);
* From-Botnet sources vs the documented initiators (missing / extra);
* To-Botnet destinations outside the initiators;
* From-Normal sources vs the documented normal hosts;
* per initiator: first and last From-Botnet StartTime as written in the file (time zone not
  assumed) next to the documented infection time.
Usage: uv run python scripts/phase8g/provenance_audit.py [--config path]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows import initiators, load_config  # noqa: E402

NEEDED = ("StartTime", "SrcAddr", "DstAddr", "Label")


def family(col: pl.Expr) -> pl.Expr:
    return (pl.when(col.str.contains("From-Botnet")).then(pl.lit("From-Botnet"))
            .when(col.str.contains("To-Botnet")).then(pl.lit("To-Botnet"))
            .when(col.str.contains("From-Normal")).then(pl.lit("From-Normal"))
            .when(col.str.contains("To-Normal")).then(pl.lit("To-Normal"))
            .when(col.str.contains("Background")).then(pl.lit("Background"))
            .when(col.str.contains("C&C|CC", literal=False)).then(pl.lit("C&C"))
            .otherwise(pl.lit("other")))  # fmt: skip


def audit_file(path: Path, init: set[str], benign: set[str], infected: dict) -> dict:
    header = path.open("r", encoding="utf-8", errors="replace").readline().strip().split(",")
    if not set(NEEDED) <= set(header):
        return {"file": path.name, "has_label_column": False, "header": header}
    lf = pl.scan_csv(path, schema_overrides={c: pl.Utf8 for c in NEEDED},
                     infer_schema_length=0).select(list(NEEDED))  # fmt: skip
    lf = lf.with_columns(family(pl.col("Label")).alias("family"))
    fams = dict(lf.group_by("family").len().collect().iter_rows())
    fb = (lf.filter(pl.col("family") == "From-Botnet").group_by("SrcAddr")
          .agg(pl.len().alias("flows"), pl.col("StartTime").min().alias("first"),
               pl.col("StartTime").max().alias("last")).collect())  # fmt: skip
    srcs = set(fb["SrcAddr"].to_list())
    tb = set(lf.filter(pl.col("family") == "To-Botnet").select("DstAddr").unique().collect()[
        "DstAddr"].to_list())  # fmt: skip
    fn = set(lf.filter(pl.col("family") == "From-Normal").select("SrcAddr").unique().collect()[
        "SrcAddr"].to_list())  # fmt: skip
    per = {r["SrcAddr"]: {"from_botnet_flows": r["flows"], "first_start_time": r["first"],
                          "last_start_time": r["last"],
                          "documented_infection_utc": infected.get(r["SrcAddr"])}
           for r in fb.iter_rows(named=True)}  # fmt: skip
    return {"file": path.name, "has_label_column": True, "families": fams,
            "from_botnet_sources_not_documented": sorted(srcs - init),
            "documented_initiators_without_from_botnet": sorted(init - srcs),
            "to_botnet_destinations_not_documented": sorted(tb - init),
            "from_normal_sources": sorted(fn),
            "from_normal_not_in_documented_benign": sorted(fn - benign),
            "documented_benign_without_from_normal": sorted(benign - fn),
            "initiators": per,
            "time_zone_note": "StartTime strings as written; the file's time zone is not "
                              "assumed (README times are CEST = UTC+2)"}  # fmt: skip


def run(cfg: dict) -> dict:
    rep = Path(cfg["reports_root"])
    res = rep / "results.json"
    if not res.exists() or json.loads(res.read_text("utf-8")).get("status") != "complete":
        raise SystemExit("frozen evaluation results missing: labels stay blinded")
    init = initiators(cfg)
    out = {}
    for key, sc in cfg["scenarios"].items():
        infected = {cfg["initiator_names"][n]: t for n, t in sc["infected_utc"].items()}
        out[key] = [audit_file(Path(cfg["data_root"]) / sc["id"] / f, init, set(sc["benign"]),
                               infected) for f in sc["label_files"]]  # fmt: skip
    (rep / "provenance.json").write_text(json.dumps(out, indent=1, default=str), "utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/phase8g/ctu13.yaml")
    a = ap.parse_args()
    print(json.dumps(run(load_config(a.config)), indent=1, default=str)[:20000])
