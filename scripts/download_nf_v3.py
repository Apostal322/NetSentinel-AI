"""Resumable download of the NetFlow v3 zips listed in configs/datasets/nf_v3.yaml.

The UQ RDM API returns a pre-signed S3 URL valid for one hour; on any failure the script asks
for a fresh URL and resumes with an HTTP Range request. Verify afterwards with
`uv run netsentinel data verify --manifest configs/datasets/nf_v3.yaml`.

Usage: uv run python scripts/download_nf_v3.py
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "configs/datasets/nf_v3.yaml"
CHUNK = 1 << 20


def signed_url(uuid: str) -> str:
    with urllib.request.urlopen(f"https://api.rdm.uq.edu.au/datasets/{uuid}/download",
                                timeout=60) as r:  # fmt: skip
        return json.loads(r.read())["url"]


def fetch(uuid: str, dest: Path, size: int) -> None:
    for attempt in range(1, 11):
        have = dest.stat().st_size if dest.exists() else 0
        if have == size:
            print(f"ok {dest.name}")
            return
        if have > size:
            raise RuntimeError(f"{dest} larger than expected; delete it and retry")
        print(f"fetch {dest.name}: {have}/{size} bytes (attempt {attempt})", flush=True)
        try:
            req = urllib.request.Request(signed_url(uuid), headers={"Range": f"bytes={have}-"})
            with urllib.request.urlopen(req, timeout=120) as r, dest.open("ab") as fh:
                if have and r.status != 206:
                    raise RuntimeError(f"server ignored Range request (status {r.status})")
                while block := r.read(CHUNK):
                    fh.write(block)
        except (OSError, RuntimeError) as exc:
            print(f"  interrupted: {exc}; retrying", flush=True)
            time.sleep(10)
    if dest.stat().st_size != size:
        raise RuntimeError(f"giving up on {dest.name}")


def main() -> int:
    m = yaml.safe_load(MANIFEST.read_text("utf-8"))
    out = ROOT / m["local_dir"]
    out.mkdir(parents=True, exist_ok=True)
    for f in m["files"]:
        fetch(f["rdm_uuid"], out / f["name"], int(f["size"]))
    print("all downloads finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
