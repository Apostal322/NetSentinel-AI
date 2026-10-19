"""Label-quality probes motivated by Liu, Engelen et al. (CNS 2022) and the DistriNet notes.

1. Protocol / port mix per attack label (e.g. UDP flows labelled LOIC-HTTP on 2018-02-20).
2. FTP-BruteForce (02-14) vs DoS-SlowHTTPTest (02-16): both reportedly hit the closed port 21.
   How many distinct feature vectors do they share?
3. Infiltration vs benign: share of infiltration rows whose exact feature vector also occurs
   labelled benign (on the same day).
Writes reports/eda/label_quality.json.
"""

import json
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from netsentinel.features.schema import raw_flow_columns  # noqa: E402

interim = Path("data/interim/ids2018")
FEATS = [*raw_flow_columns(), "dst_port", "protocol"]


def scan(day: str) -> pl.LazyFrame:
    return pl.scan_parquet(interim / f"{day}.parquet")


def h(lf: pl.LazyFrame) -> pl.LazyFrame:
    return lf.with_columns(pl.struct(FEATS).hash(seed=0).alias("h"))


out: dict = {}
mix = []
for p in sorted(interim.glob("2018-*.parquet")):
    df = (
        pl.scan_parquet(p)
        .filter(pl.col("label") != "benign")
        .group_by("label", "protocol", "dst_port")
        .agg(pl.len().alias("rows"))
        .collect()
    )
    tot = df.group_by("label").agg(pl.col("rows").sum().alias("tot"))
    df = df.join(tot, on="label").with_columns((pl.col("rows") / pl.col("tot")).alias("share"))
    mix += df.filter(pl.col("share") > 0.005).with_columns(pl.lit(p.stem).alias("day")).to_dicts()
out["protocol_port_mix"] = sorted(mix, key=lambda r: (r["day"], r["label"], -r["rows"]))

ftp = h(scan("2018-02-14").filter(pl.col("label") == "ftp_bruteforce")).select("h").collect()
slow = h(scan("2018-02-16").filter(pl.col("label") == "dos_slowhttptest")).select("h").collect()
shared = set(ftp["h"].unique()) & set(slow["h"].unique())
out["ftp_vs_slowhttptest"] = {
    "ftp_rows": ftp.height,
    "ftp_distinct_vectors": ftp["h"].n_unique(),
    "slowhttptest_rows": slow.height,
    "slowhttptest_distinct_vectors": slow["h"].n_unique(),
    "shared_distinct_vectors": len(shared),
    "ftp_rows_with_shared_vector": int(ftp["h"].is_in(list(shared)).sum()),
    "slowhttptest_rows_with_shared_vector": int(slow["h"].is_in(list(shared)).sum()),
}

inf = {}
for day in ("2018-02-28", "2018-03-01"):
    lf = h(scan(day))
    ben = lf.filter(pl.col("label") == "benign").select("h").unique()
    att = lf.filter(pl.col("label") == "infiltration").select("h")
    n = att.select(pl.len()).collect().item()
    dup = att.join(ben, on="h", how="semi").select(pl.len()).collect().item()
    inf[day] = {"infiltration_rows": n, "rows_identical_to_a_benign_row": dup,
                "share": dup / n if n else None}  # fmt: skip
out["infiltration_vs_benign"] = inf

Path("reports/eda/label_quality.json").write_text(json.dumps(out, indent=2), "utf-8")
print(json.dumps({k: v for k, v in out.items() if k != "protocol_port_mix"}, indent=2))
for r in out["protocol_port_mix"]:
    print(f"{r['day']} {r['label']:18s} proto={r['protocol']:>2} port={r['dst_port']:>5} "
          f"rows={r['rows']:>8,} share={r['share']:.3f}")  # fmt: skip
