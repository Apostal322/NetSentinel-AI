"""Phase 8e M4: global- and service-level windows for the DEVELOPMENT captures, built with the
unchanged Phase 8b harness protocol (only the window level differs). Cached under
data/derived/phase8e/<level>/<capture>/. Device windows are the cached Phase 8b ones.
Usage: uv run python scripts/phase8e/population_windows.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8b"))
import harness  # noqa: E402
from dev_compare import dev_captures  # noqa: E402

from netsentinel.resources import peak_rss_mb  # noqa: E402

OUT = Path("data/derived/phase8e")
STATUS = Path("reports/phase8e/population_windows_status.json")


def main() -> None:
    log = {}
    for level in ("global", "service"):
        harness.LEVEL = level  # WindowBuilder reads the module-level LEVEL at call time
        for name, src in dev_captures().items():
            out = OUT / level / name
            if (out / "meta.json").exists():
                continue
            t0 = time.time()
            if src == "nf_unsw":
                harness.nf_unsw_windows(out)
            else:
                harness.zeek_windows(Path(src), out)
            log[f"{level}/{name}"] = {"seconds": round(time.time() - t0, 1),
                                      "peak_rss_mb": peak_rss_mb()}  # fmt: skip
            STATUS.write_text(json.dumps(log, indent=1), "utf-8")
            print(level, name, log[f"{level}/{name}"], flush=True)
    STATUS.write_text(json.dumps({**log, "done": True}, indent=1), "utf-8")


if __name__ == "__main__":
    main()
