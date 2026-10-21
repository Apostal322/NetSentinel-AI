"""Dependency metadata gate (docs/security/DEPENDENCY_EXCEPTIONS.md).

Checks the INSTALLED environment, like `uv pip check`, but with an explicit allow-list:
1. every installed distribution's requirements are satisfied, except the documented,
   accepted exceptions below; any other conflict fails;
2. an accepted exception that is no longer needed fails too, so the override is removed promptly
   (e.g. once Streamlit's own metadata allows Pillow 13);
3. security floors are enforced (Pillow >= 13.0.0, advisories of 2026-10-20).
`--online` additionally asks PyPI whether the newest Streamlit release allows Pillow 13 and
prints a GitHub Actions warning if so (network failures are only reported).

Usage: uv run --extra dashboard python scripts/release/check_dependency_exceptions.py [--online]
Exit code 0 = OK, 1 = violation.
"""

from __future__ import annotations

import json
import sys
import tomllib
import urllib.request
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]
# (dependent, dependency): why it is accepted and when it ends
ACCEPTED = {
    ("streamlit", "pillow"): {
        "reason": "streamlit<=1.66.0 declares pillow<13; Pillow 13.0.0 fixes the 2026-10-20 "
                  "advisories (e.g. GHSA-8g5g-8vmr-9782). Forced by [tool.uv] "
                  "override-dependencies in pyproject.toml.",
        "upstream": "https://github.com/streamlit/streamlit/pull/17589",
        "ends_when": "the installed Streamlit's own metadata allows the installed Pillow",
    },
}  # fmt: skip
FLOORS = {"pillow": Version("13.0.0"), "certifi": Version("2026.10.19")}


def installed() -> dict[str, metadata.Distribution]:
    out = {}
    for d in metadata.distributions():
        name = d.metadata["Name"]
        if name:
            out[canonicalize_name(name)] = d
    return out


def conflicts(dists: dict[str, metadata.Distribution]) -> list[dict]:
    env = {"extra": ""}
    found = []
    for name, d in sorted(dists.items()):
        for raw in d.requires or []:
            req = Requirement(raw)
            if req.marker is not None and not req.marker.evaluate(env):
                continue  # optional extra or other platform
            dep = canonicalize_name(req.name)
            if dep not in dists:
                found.append({"dependent": name, "dependency": dep, "required": str(req.specifier),
                              "installed": None})  # fmt: skip
                continue
            v = Version(dists[dep].version)
            if req.specifier and not req.specifier.contains(v, prereleases=True):
                found.append({"dependent": name, "dependency": dep,
                              "required": str(req.specifier), "installed": str(v)})  # fmt: skip
    return found


def override_declared() -> list[str]:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    return cfg.get("tool", {}).get("uv", {}).get("override-dependencies", [])


def online_hint() -> str | None:
    try:
        with urllib.request.urlopen("https://pypi.org/pypi/streamlit/json", timeout=10) as r:
            info = json.load(r)["info"]
    except Exception as exc:  # noqa: BLE001 - informational only
        return f"online check skipped: {exc}"
    for raw in info.get("requires_dist") or []:
        req = Requirement(raw)
        if canonicalize_name(req.name) == "pillow":
            if SpecifierSet(str(req.specifier)).contains(FLOORS["pillow"]):
                return (f"::warning::streamlit {info['version']} on PyPI allows Pillow "
                        f"{FLOORS['pillow']} ({req.specifier}): upgrade streamlit and remove the "
                        "pillow override (docs/security/DEPENDENCY_EXCEPTIONS.md)")  # fmt: skip
            return f"streamlit {info['version']} on PyPI still requires pillow{req.specifier}"
    return None


def check(dists=None) -> tuple[list[str], list[str]]:
    """Returns (errors, notes)."""
    dists = installed() if dists is None else dists
    errors, notes = [], []
    found = conflicts(dists)
    seen = set()
    for c in found:
        key = (c["dependent"], c["dependency"])
        if key in ACCEPTED:
            seen.add(key)
            notes.append(f"accepted exception: {c['dependent']} requires {c['dependency']}"
                         f"{c['required']}, installed {c['installed']} ({ACCEPTED[key]['upstream']})")  # fmt: skip
        else:
            errors.append(f"dependency conflict: {c['dependent']} requires {c['dependency']}"
                          f"{c['required']}, installed {c['installed']}")  # fmt: skip
    for key, info in ACCEPTED.items():
        dependent, dependency = key
        if dependent in dists and dependency in dists and key not in seen:
            errors.append(f"accepted exception {dependent}->{dependency} is no longer needed "
                          f"({info['ends_when']}): remove the override from pyproject.toml, "
                          "re-lock, and update docs/security/DEPENDENCY_EXCEPTIONS.md")  # fmt: skip
    for pkg, floor in FLOORS.items():
        if pkg in dists and Version(dists[pkg].version) < floor:
            errors.append(f"security floor: {pkg} {dists[pkg].version} < {floor}")
    ov = override_declared()
    if seen and not any(o.lower().startswith("pillow") for o in ov):
        errors.append("Pillow exception present but no override-dependencies entry declares it")
    return errors, notes


def main() -> int:
    errors, notes = check()
    for n in notes:
        print(n)
    if "--online" in sys.argv:
        hint = online_hint()
        if hint:
            print(hint)
    for e in errors:
        print(f"ERROR: {e}")
    print("dependency gate:", "FAILED" if errors else "OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
