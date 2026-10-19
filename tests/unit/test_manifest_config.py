import hashlib

import pytest

from netsentinel.config import load_config
from netsentinel.data.manifest import Manifest, s3_multipart_etag, verify


def test_multipart_etag_matches_s3_definition(tmp_path):
    data = b"a" * 10 + b"b" * 10 + b"c" * 5
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    parts = [data[0:10], data[10:20], data[20:25]]
    expected = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest() + "-3"
    assert s3_multipart_etag(path, part_size=10) == expected
    assert s3_multipart_etag(path, part_size=100) == hashlib.md5(data).hexdigest()


def test_verify_reports_each_failure_mode(tmp_path):
    (tmp_path / "raw").mkdir()
    good = tmp_path / "raw" / "good.csv"
    good.write_bytes(b"x" * 20)
    (tmp_path / "raw" / "short.csv").write_bytes(b"x")
    (tmp_path / "raw" / "tampered.csv").write_bytes(b"y" * 20)
    etag = s3_multipart_etag(good, 10)
    (tmp_path / "m.yaml").write_text(
        f"""name: t
version: "1"
base_url: "http://example.invalid/"
local_dir: raw
part_size_bytes: 10
files:
  - {{name: good.csv, day: d1, size: 20, etag: "{etag}"}}
  - {{name: short.csv, day: d2, size: 20, etag: "{etag}"}}
  - {{name: tampered.csv, day: d3, size: 20, etag: "{etag}"}}
  - {{name: absent.csv, day: d4, size: 20, etag: "{etag}"}}
""",
        encoding="utf-8",
    )
    results = {r.name: r.status for r in verify(Manifest.load(tmp_path / "m.yaml", tmp_path))}
    assert results == {
        "good.csv": "ok",
        "short.csv": "size_mismatch",
        "tampered.csv": "etag_mismatch",
        "absent.csv": "missing",
    }


def test_real_manifest_is_well_formed():
    m = Manifest.load("configs/datasets/cse_cic_ids2018.yaml")
    assert len(m.files) == 10
    assert all(f.etag.count("-") == 1 for f in m.files)


def test_config_overrides(tmp_path):
    (tmp_path / "c.yaml").write_text("a: {b: 1}\nseed: 0\n", encoding="utf-8")
    cfg = load_config(tmp_path / "c.yaml", sets=["a.b=2.5", "new.key=[1,2]"])
    assert cfg == {"a": {"b": 2.5}, "seed": 0, "new": {"key": [1, 2]}}
    with pytest.raises(ValueError):
        load_config(tmp_path / "c.yaml", sets=["novalue"])
