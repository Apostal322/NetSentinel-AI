"""The dependency gate (scripts/release/check_dependency_exceptions.py): the documented Pillow
exception is accepted, any other conflict fails, the exception fails once it is no longer
needed (so the override gets removed), and security floors hold."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "check_dependency_exceptions", ROOT / "scripts/release/check_dependency_exceptions.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class Dist:
    def __init__(self, name, version, requires=()):
        self.metadata = {"Name": name}
        self.version = version
        self.requires = list(requires)


def env(**over):
    d = {"streamlit": Dist("streamlit", "1.66.0", ["pillow<13,>=9.2.0", "numpy<3"]),
         "pillow": Dist("pillow", "13.0.0"), "numpy": Dist("numpy", "2.5.4"),
         "certifi": Dist("certifi", "2026.10.19")}  # fmt: skip
    d.update(over)
    return d


def test_documented_exception_is_accepted():
    errors, notes = gate.check(env())
    assert errors == [] and any("accepted exception" in n for n in notes)


def test_other_conflicts_fail():
    errors, _ = gate.check(env(numpy=Dist("numpy", "3.1.0")))
    assert any("streamlit requires numpy" in e for e in errors)


def test_exception_no_longer_needed_fails_so_the_override_is_removed():
    fixed = Dist("streamlit", "1.67.0", ["pillow<14,>=9.2.0", "numpy<3"])
    errors, _ = gate.check(env(streamlit=fixed))
    assert any("no longer needed" in e for e in errors)


def test_security_floors():
    errors, _ = gate.check(env(pillow=Dist("pillow", "12.3.0")))
    assert any("security floor: pillow" in e for e in errors)
    errors, _ = gate.check(env(certifi=Dist("certifi", "2026.10.18")))
    assert any("security floor: certifi" in e for e in errors)


def test_installed_environment_passes_the_gate():
    errors, _ = gate.check()
    assert errors == [], errors


def test_extras_markers_are_ignored():
    reqs = ["pillow<13,>=9.2.0", 'snowflake>=1; extra == "snowflake"']
    d = env(streamlit=Dist("streamlit", "1.66.0", reqs))
    errors, _ = gate.check(d)
    assert errors == []
