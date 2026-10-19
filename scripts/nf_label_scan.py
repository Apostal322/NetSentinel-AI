"""Stream the `Attack` / `Label` columns and flow-start range of a NetFlow v3 zip (no ingest),
to define the family map before ingestion.

Usage: uv run python scripts/nf_label_scan.py data/raw/nf_v3/NF-CICIDS2018-v3.zip
"""

import io
import sys
import zipfile
from collections import Counter

import pyarrow as pa
import pyarrow.csv as pacsv

path = sys.argv[1]
with zipfile.ZipFile(path) as z:
    member = next(n for n in z.namelist() if "/data/" in n and n.endswith(".csv")
                  and "Features" not in n)  # fmt: skip
    with z.open(member) as raw:
        header = io.TextIOWrapper(raw, encoding="utf-8").readline().strip().split(",")
    counts: Counter = Counter()
    lo, hi = None, None
    with z.open(member) as raw:
        reader = pacsv.open_csv(
            pa.PythonFile(raw, mode="r"),
            read_options=pacsv.ReadOptions(block_size=64 << 20),
            convert_options=pacsv.ConvertOptions(
                include_columns=["FLOW_START_MILLISECONDS", "Label", "Attack"],
                column_types={"FLOW_START_MILLISECONDS": pa.int64(), "Label": pa.int64(),
                              "Attack": pa.string()},
            ),
        )  # fmt: skip
        for batch in reader:
            t = batch.column("FLOW_START_MILLISECONDS")
            import pyarrow.compute as pc

            mn, mx = pc.min(t).as_py(), pc.max(t).as_py()
            lo = mn if lo is None else min(lo, mn)
            hi = mx if hi is None else max(hi, mx)
            for (lab, att), n in Counter(zip(batch.column("Label").to_pylist(),
                                             batch.column("Attack").to_pylist(),
                                             strict=True)).items():  # fmt: skip
                counts[(lab, att)] += n
print(f"member={member} columns={len(header)} start_ms=[{lo}, {hi}]")
for (lab, att), n in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"Label={lab} Attack={att!r}: {n:,}")
