"""Calibration registry: which behaviour profile is active, its history, and rollback.

Profiles are immutable artifacts (behavior/calibrate.py). Adaptation is an explicit new
`calibrate` run, never online learning. A new profile can be compared with the active one
(`update_check`): if the new calibration period looks anomalous under the CURRENT baseline,
the artifact is marked `review_required`, because it may contain attack traffic that would
otherwise become "normal". Such a profile is only activated with an explicit `reviewed=True`.

Layout: <root>/registry.json = {"active": <id> | null, "history": [{id, activated_utc,
reviewed, note}]}; artifacts live in <root>/<id>/.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl

DEFAULT_ROOT = Path("models/calibrations")


def _reg_path(root: Path) -> Path:
    return Path(root) / "registry.json"


def read_registry(root: str | Path = DEFAULT_ROOT) -> dict[str, Any]:
    p = _reg_path(Path(root))
    if not p.exists():
        return {"active": None, "history": []}
    return json.loads(p.read_text("utf-8"))


def _write(root: Path, reg: dict) -> None:
    p = _reg_path(root)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2), "utf-8")
    tmp.replace(p)  # atomic on the same volume


def resolve_calibration(arg: str | Path | None, root: str | Path = DEFAULT_ROOT) -> Path | None:
    """`active` -> the registry's active artifact; anything else is used as a path."""
    if arg is None:
        return None
    if str(arg) == "active":
        reg = read_registry(root)
        if not reg.get("active"):
            raise FileNotFoundError(f"no active calibration in {_reg_path(Path(root))}")
        return Path(root) / reg["active"]
    return Path(arg)


def activate(cid: str, root: str | Path = DEFAULT_ROOT, reviewed: bool = False,
             note: str = "") -> dict:  # fmt: skip
    from netsentinel.behavior.calibrate import load_profile

    root = Path(root)
    _, manifest = load_profile(root / cid)  # refuses corrupt / incompatible artifacts
    check = manifest.get("update_check") or {}
    if check.get("review_required") and not reviewed:
        raise ValueError(
            f"{cid} requires review before activation: {check.get('reason')}; "
            "re-run with reviewed=True (--reviewed) once the period is vetted"
        )
    reg = read_registry(root)
    reg["active"] = cid
    reg["history"].append({"id": cid, "activated_utc": datetime.now(UTC).isoformat(
        timespec="seconds"), "reviewed": bool(reviewed), "note": note})  # fmt: skip
    _write(root, reg)
    return reg


def rollback(root: str | Path = DEFAULT_ROOT) -> dict:
    """Re-activate the previously active calibration (history is kept, never deleted)."""
    root = Path(root)
    reg = read_registry(root)
    ids = [h["id"] for h in reg["history"]]
    if len(ids) < 2:
        raise ValueError("no previous calibration to roll back to")
    current = reg["active"]
    previous = next((i for i in reversed(ids[:-1]) if i != current), None)
    if previous is None:
        raise ValueError("no previous calibration to roll back to")
    reg["active"] = previous
    reg["history"].append({"id": previous, "activated_utc": datetime.now(UTC).isoformat(
        timespec="seconds"), "reviewed": True, "note": f"rollback from {current}"})  # fmt: skip
    _write(root, reg)
    return reg


def update_check(previous_dir: str | Path, frame: pl.DataFrame, alpha: float = 0.01,
                 rate_factor: float = 2.0) -> dict:  # fmt: skip
    """Score the NEW calibration period with the CURRENT (previous) baseline. A global alert
    rate significantly above the previous target FPR means the new period differs from what
    was normal: legitimate change or attack traffic - a human must decide."""
    from scipy.stats import binom

    from netsentinel.behavior.calibrate import load_profile
    from netsentinel.behavior.monitor import score_flows

    prev, manifest = load_profile(previous_dir)
    s = score_flows(prev, frame)
    g = s.filter(pl.col("level") == "global") if s.height else s
    n = g.height
    alerts = int(g["anomalous"].sum()) if n else 0
    rate = alerts / n if n else 0.0
    p_value = float(binom.sf(alerts - 1, n, prev.target_fpr)) if alerts else 1.0
    review = bool(n and rate > rate_factor * prev.target_fpr and p_value < alpha)
    return {"previous": manifest["calibration_id"], "global_windows": n, "alerts": alerts,
            "alert_rate_under_previous": rate, "previous_target_fpr": prev.target_fpr,
            "p_value": p_value, "review_required": review,
            "reason": ("new calibration period is anomalous under the current baseline "
                       f"(alert rate {rate:.2%} vs target {prev.target_fpr:.2%}); it may "
                       "contain attack traffic or a legitimate change") if review else
                      "consistent with the current baseline"}  # fmt: skip
