"""List the members of the DEDALE Zeek archives without downloading them.

Reads only each zip's end-of-central-directory record and central directory via HTTP
range requests (names, sizes, CRCs, timestamps). No member data is fetched, so no flow
or label content is seen. Writes reports/phase8l/dedale_zip_index.json.
"""

from __future__ import annotations

import json
import struct
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "reports" / "phase8l" / "dedale_zip_index.json"
ZEEK = "https://dedale.inria.fr/data/network_logs/zeek/"
DATAVERSE = "https://entrepot.recherche.data.gouv.fr/api/access/datafile/"
# name -> (URL, Dataverse file id, size in bytes, MD5), from the Dataverse API, version 2.1
ARCHIVES = {
    "orange_dmz.zip": (
        ZEEK + "orange_dmz.zip",
        717876,
        415796741,
        "c9eeda34bb1a1591fe1874718bdc192f",
    ),
    "orange_servers.zip": (
        ZEEK + "orange_servers.zip",
        717877,
        3405887752,
        "ed2256f2f385e0755096f72d05c04707",
    ),
    "green_internal.zip": (
        ZEEK + "green_internal.zip",
        717875,
        3538305367,
        "db1e4c7a80545e758edb766d920a0400",
    ),
    "router1.zip": (ZEEK + "router1.zip", 717878, 4396439880, "c5f237d2cbc5afc4946cb2a766cf7d7e"),
    # AURA benign-activity timelines: member names give the machines that ran it
    "userbehaviour_logs.zip": (
        DATAVERSE + "717880",
        717880,
        22196076,
        "25c891442f693c4f525f930d17fedb4a",
    ),
}
TAIL = 1 << 16


def fetch(url: str, start: int, end: int) -> bytes:
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        if r.status != 206:
            raise RuntimeError(f"no range support: {r.status}")
        return r.read()


def central_directory(url: str, size: int) -> tuple[list[dict], int]:
    tail = fetch(url, size - TAIL, size - 1)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise RuntimeError("no end-of-central-directory record")
    n, cd_size, cd_off = struct.unpack("<HII", tail[i + 10 : i + 20])
    if 0xFFFF in (n,) or 0xFFFFFFFF in (cd_size, cd_off):
        j = tail.rfind(b"PK\x06\x06")
        if j < 0:
            raise RuntimeError("zip64 end-of-central-directory record not in the tail")
        n, cd_size, cd_off = struct.unpack("<QQQ", tail[j + 32 : j + 56])
    cd = fetch(url, cd_off, cd_off + cd_size - 1)
    members, p = [], 0
    while p < len(cd) and cd[p : p + 4] == b"PK\x01\x02":
        method = struct.unpack("<H", cd[p + 10 : p + 12])[0]
        (mtime, mdate, crc, csize, usize, ln, le, lc) = struct.unpack(
            "<HHIIIHHH", cd[p + 12 : p + 34]
        )
        offset = struct.unpack("<I", cd[p + 42 : p + 46])[0]
        name = cd[p + 46 : p + 46 + ln].decode("utf-8", "replace")
        extra = cd[p + 46 + ln : p + 46 + ln + le]
        q = 0
        while q + 4 <= len(extra):
            tag, sz = struct.unpack("<HH", extra[q : q + 4])
            if tag == 1:
                k = sz // 8  # a trailing 4-byte disk number, if present, is ignored
                vals = list(struct.unpack(f"<{k}Q", extra[q + 4 : q + 4 + 8 * k]))
                if usize == 0xFFFFFFFF:
                    usize = vals.pop(0)
                if csize == 0xFFFFFFFF:
                    csize = vals.pop(0)
                if offset == 0xFFFFFFFF:
                    offset = vals.pop(0)
            q += 4 + sz
        stamp = (
            f"{(mdate >> 9) + 1980:04d}-{(mdate >> 5) & 15:02d}-{mdate & 31:02d}"
            f"T{mtime >> 11:02d}:{(mtime >> 5) & 63:02d}"
        )
        members.append(
            {
                "name": name,
                "method": method,
                "offset": offset,
                "compressed": csize,
                "uncompressed": usize,
                "crc32": f"{crc:08x}",
                "mtime": stamp,
            }
        )
        p += 46 + ln + le + lc
    if len(members) != n:
        raise RuntimeError(f"parsed {len(members)} of {n} entries")
    return members, TAIL + cd_size


def main() -> None:
    report = {}
    for name, (url, fid, size, md5) in ARCHIVES.items():
        members, fetched = central_directory(url, size)
        files = [m for m in members if not m["name"].endswith("/")]
        report[name] = {
            "url": url,
            "dataverse_file_id": fid,
            "size": size,
            "md5": md5,
            "bytes_fetched_for_index": fetched,
            "n_files": len(files),
            "uncompressed_total": sum(m["uncompressed"] for m in files),
            "members": members,
        }
        print(
            name,
            len(files),
            f"{report[name]['uncompressed_total'] / 1e9:.2f} GB uncompressed",
            f"index {fetched / 1e3:.0f} kB",
        )
    OUT.write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
