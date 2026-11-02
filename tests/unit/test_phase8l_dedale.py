"""Phase 8l DEDALE tooling: central-directory parsing and member-level fetch (no network)."""

from __future__ import annotations

import gzip
import importlib.util
import io
import os
import sys
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "phase8l"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"phase8l_{name}", SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


IDX = _load("dedale_zip_index")
FETCH = _load("dedale_fetch")


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class _Resp(io.BytesIO):
    status = 206


def _opener(blob: bytes):
    return lambda url, start, end: _Resp(blob[start : end + 1])


def _files() -> dict[str, bytes]:
    out = {}
    for d in (1, 14, 15, 28):
        date = f"2025-01-{d:02d}"
        base = f"green_internal/D{d}_{date}_output_green_internal_Zeek/"
        out[base + "conn_labeled.csv"] = (f"ts;label\n{d};0\n" * 5000).encode()
        out[base + "dhcp.log"] = os.urandom(300)
        out[base + "conn.log"] = b"unused"
    return out


def _index(blob: bytes, monkeypatch) -> dict:
    monkeypatch.setattr(IDX, "fetch", lambda url, s, e: blob[max(s, 0) : e + 1])
    members, _ = IDX.central_directory("mem://", len(blob))
    return {"green_internal.zip": {"url": "mem://", "dataverse_file_id": 0, "size": len(blob),
                                   "md5": "", "members": members}}  # fmt: skip


def test_central_directory_matches_zipfile(monkeypatch):
    files = _files()
    blob = _zip(files)
    members = _index(blob, monkeypatch)["green_internal.zip"]["members"]
    ref = {i.filename: i for i in zipfile.ZipFile(io.BytesIO(blob)).infolist()}
    assert [m["name"] for m in members] == list(ref)
    for m in members:
        i = ref[m["name"]]
        assert (m["offset"], m["compressed"], m["uncompressed"]) == (
            i.header_offset,
            i.compress_size,
            i.file_size,
        )
        assert m["crc32"] == f"{i.CRC:08x}" and m["method"] == 8


def test_select_stages(monkeypatch):
    idx = _index(_zip(_files()), monkeypatch)
    monkeypatch.setattr(FETCH, "STAGES", {"A": (1, 14), "B": (15, 28)})
    a, b = FETCH.select(idx, "A"), FETCH.select(idx, "B")
    assert {m["day"] for m in a} == {1, 14} and {m["day"] for m in b} == {15, 28}
    assert {m["file"] for m in a + b} == {"conn_labeled.csv", "dhcp.log"}
    monkeypatch.setattr(FETCH, "STAGES", {"A": range(1, 15)})
    with pytest.raises(SystemExit):  # 14 days expected, 2 present
        FETCH.select(idx, "A")


def test_fetch_member_roundtrip_and_crc_check(monkeypatch, tmp_path):
    files = _files()
    blob = _zip(files)
    idx = _index(blob, monkeypatch)
    for m in idx["green_internal.zip"]["members"]:
        if not m["name"].endswith(("conn_labeled.csv", "dhcp.log")):
            continue
        dest = tmp_path / (Path(m["name"]).name + ".gz")
        got = FETCH.fetch_member("mem://", m, dest, opener=_opener(blob))
        assert gzip.decompress(dest.read_bytes()) == files[m["name"]]
        assert got["crc32"] == m["crc32"]
    bad = {**m, "crc32": "00000000"}
    with pytest.raises(RuntimeError):
        FETCH.fetch_member("mem://", bad, tmp_path / "bad.gz", opener=_opener(blob))
    assert not (tmp_path / "bad.gz").exists()


def test_fetch_member_rejects_wrong_local_header(monkeypatch, tmp_path):
    files = _files()
    blob = _zip(files)
    m = next(x for x in _index(blob, monkeypatch)["green_internal.zip"]["members"]
             if x["name"].endswith("conn_labeled.csv"))  # fmt: skip
    other = {**m, "name": m["name"].replace("D1_", "D9_")}
    with pytest.raises(RuntimeError, match="local header"):
        FETCH.fetch_member("mem://", other, tmp_path / "x.gz", opener=_opener(blob))


def test_stage_b_locked_without_freeze(monkeypatch, tmp_path):
    monkeypatch.setattr(FETCH, "FREEZE", tmp_path / "missing.md")
    with pytest.raises(SystemExit, match="locked"):
        FETCH.download("B")


def test_freeze_must_hold_the_preregistration_hash(tmp_path):
    prereg = tmp_path / "pre.md"
    prereg.write_bytes(b"rule\r\n")
    freeze = tmp_path / "FREEZE.md"
    freeze.write_text("no hash here", "utf-8")
    assert not FETCH.freeze_ok(freeze, prereg)  # wrong content (and not tracked in git)
    assert not FETCH.freeze_ok(tmp_path / "absent.md", prereg)


STAGE_A = _load("dedale_stage_a")


def test_stage_a_parse_day_and_canonical(tmp_path):
    hdr = ("date;ts;uid;ip_src;port_src;ip_dst;port_dst;proto;service;duration;orig_bytes;"
           "resp_bytes;conn_state;local_orig;local_resp;missed_bytes;history;orig_pkts;"
           "orig_ip_bytes;resp_pkts;resp_ip_bytes;tunnel_parents;ip_proto;label;step;"
           "attack_step;tactic;technique;comments")  # fmt: skip
    day0 = 1734912000.0  # 2024-12-23 00:00 UTC
    tail = ";1;1;{st};T;F;0;{h};{op};{ob};{rp};{rb};-;{ip};0;0;benign;;;"
    rows = [
        f"d;{day0 + 60};u;172.16.1.10;5;8.8.8.8;53;udp;dns;0.5"
        + tail.format(st="SF", h="Dd", op=1, ob=60, rp=1, rb=80, ip=17),
        f"d;{day0 + 120};u;172.16.1.10;5;1.1.1.1;443;tcp;ssl;2"
        + tail.format(st="RSTO", h="ShR", op=3, ob=200, rp=2, rb=100, ip=6),
        "d;bad;u;172.16.1.10;5;1.1.1.1;443;tcp;ssl;2"
        + tail.format(st="SF", h="Sh", op=3, ob=200, rp=2, rb=100, ip=6),
    ]
    p = tmp_path / "c.csv.gz"
    p.write_bytes(gzip.compress(("\n".join([hdr, *rows]) + "\n").encode()))
    flows, info = STAGE_A.parse_day(p, 1)
    assert info["rows"] == 3 and info["unparseable"] == 1 and info["labels"] == {"0": 2}
    assert info["ending_outside_utc_day_2h"] == 0 and flows.height == 2
    assert flows["client_tcp_flags"].to_list() == [0, 4] and flows["protocol"].to_list() == [17, 6]
    assert flows["flow_end_milliseconds"][1] == int((day0 + 120) * 1000) + 2000
    assert set(flows["label"]) == {"benign"}


def test_stage_a_dhcp_and_helpers(tmp_path):
    log = ("#separator \x09\n#fields\tts\tuids\tclient_addr\tserver_addr\tmac\thost_name\t"
           "client_fqdn\tdomain\trequested_addr\tassigned_addr\n#types\t...\n"
           "1.0\tC1\t172.16.1.4\t172.16.0.2\taa:bb\tCLIENT3\t-\t-\t-\t172.16.1.4\n"
           "2.0\tC2\t-\t-\tcc:dd\t-\t-\t-\t-\t-\n#close\tx\n")  # fmt: skip
    p = tmp_path / "d.log.gz"
    p.write_bytes(gzip.compress(log.encode()))
    leases = STAGE_A.dhcp_leases(p)
    assert len(leases) == 1 and leases[0]["mac"] == "aa:bb"
    assert STAGE_A.client_number("CLIENT3") == 3 and STAGE_A.client_number("dc") is None
    assert STAGE_A.split_cut(__import__("numpy").arange(10, 20)) == 17
    assert abs(STAGE_A.kish(__import__("numpy").array([1, 1, 2])) - 16 / 6) < 1e-12
