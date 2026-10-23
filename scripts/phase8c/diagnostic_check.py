"""Phase 8c: does the new tail diagnostic fire where the deployed detector failed?
Applies the product calibration (with the diagnostic) to cached development windows and,
RETROSPECTIVELY, to the consumed Phase 8b captures. Usage: uv run python scripts/phase8c/diagnostic_check.py"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase8b"))
from trace import CAPTURES  # noqa: E402

from harness import load  # noqa: E402

from netsentinel.behavior.calibrate import calibrate_windows  # noqa: E402

res = {}
for n, (root, role) in CAPTURES.items():
    p = Path(root) / n
    if not (p / "meta.json").exists():
        continue
    lp = calibrate_windows({"device": load(p)["cal_clean"]}, 0, target_fpr=0.01, min_windows=30,
                           mode="vetted_benign", threshold_method="crossfit")["device"]  # fmt: skip
    warned = any("WITHOUT an own profile" in w for w in lp.warnings)
    res[n] = {"role": role, "tail_fallback_share": lp.tail_fallback_share, "warned": warned,
              "threshold_reliable": lp.threshold_diag.get("reliable")}  # fmt: skip
    print(n, res[n])
Path("reports/phase8c/diagnostic_check.json").write_text(json.dumps(res, indent=1), "utf-8")
