"""Phase 8e (POST-HOC regression check on the consumed ToN_IoT input): does the new clock
state machine (quarantine, pending jumps, interleave check) still give exactly the reference
window membership on real data with a genuine 460 h gap? Reuses scripts/phase8d/stream_audit.py.
Usage: uv run python scripts/phase8e/ton_stream_regression.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8d"))
from stream_audit import compare, reference, stream  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

ref = reference()
fp, how, stats = stream(resync_after=1000)
kinds = {k: sum(1 for v in how.values() if v[0] == k) for k in ("watermark", "forced", "flush")}
res = {"role": "post-hoc regression on consumed ToN_IoT input", "stats": stats,
       "close_kinds": kinds, "vs_reference": compare(fp, ref), "peak_rss_mb": peak_rss_mb()}  # fmt: skip
Path("reports/phase8e/ton_stream_regression.json").write_text(json.dumps(res, indent=1), "utf-8")
print(json.dumps(res, indent=1))
