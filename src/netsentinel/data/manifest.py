"""Dataset manifests (configs/datasets/*.yaml) and download verification.

S3 multipart ETags are `md5(md5(part_1) || ... || md5(part_n))-n`, so they can be recomputed
locally when the part size is known. That gives an end-to-end integrity check against the
authoritative bucket listing without trusting the transfer."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netsentinel.config import load_yaml

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ManifestFile:
    name: str
    day: str
    size: int
    etag: str


@dataclass(frozen=True)
class Manifest:
    name: str
    version: str
    base_url: str
    local_dir: Path
    part_size_bytes: int
    files: tuple[ManifestFile, ...]

    @classmethod
    def load(cls, path: str | Path, root: str | Path = ".") -> Manifest:
        raw: dict[str, Any] = load_yaml(path)
        missing = {"name", "version", "base_url", "local_dir", "files"} - raw.keys()
        if missing:
            raise ValueError(f"Manifest {path} is missing keys: {sorted(missing)}")
        files = tuple(
            ManifestFile(str(f["name"]), str(f["day"]), int(f["size"]), str(f["etag"]))
            for f in raw["files"]
        )
        if len({f.name for f in files}) != len(files):
            raise ValueError(f"Manifest {path} lists a file twice")
        return cls(
            name=raw["name"],
            version=str(raw["version"]),
            base_url=raw["base_url"],
            local_dir=Path(root) / raw["local_dir"],
            part_size_bytes=int(raw.get("part_size_bytes", 16 * 1024 * 1024)),
            files=files,
        )

    def path_of(self, f: ManifestFile) -> Path:
        return self.local_dir / f.name


def s3_multipart_etag(path: str | Path, part_size: int) -> str:
    digests = []
    with Path(path).open("rb") as fh:
        while block := fh.read(part_size):
            digests.append(hashlib.md5(block).digest())
    if len(digests) == 1:
        return digests[0].hex()  # single-part uploads use the plain MD5
    return f"{hashlib.md5(b''.join(digests)).hexdigest()}-{len(digests)}"


@dataclass(frozen=True)
class VerifyResult:
    name: str
    status: str  # "ok" | "missing" | "size_mismatch" | "etag_mismatch"
    detail: str = ""


def verify(manifest: Manifest, check_etag: bool = True) -> list[VerifyResult]:
    results = []
    for f in manifest.files:
        path = manifest.path_of(f)
        if not path.is_file():
            results.append(VerifyResult(f.name, "missing"))
            continue
        size = path.stat().st_size
        if size != f.size:
            results.append(VerifyResult(f.name, "size_mismatch", f"{size} != {f.size}"))
            continue
        if check_etag:
            etag = s3_multipart_etag(path, manifest.part_size_bytes)
            if etag != f.etag:
                results.append(VerifyResult(f.name, "etag_mismatch", f"{etag} != {f.etag}"))
                continue
        results.append(VerifyResult(f.name, "ok"))
        log.info("verified %s", f.name)
    return results
