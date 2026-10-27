"""Phase 8g: record size and SHA-256 of the approved CTU-13 downloads (docs/phase8f/PREREG_CTU13.md).

Reads each file only as raw bytes for hashing; nothing is parsed or inspected. Compares the size
with the server's Content-Length recorded before the download.
Usage: uv run python scripts/phase8g/register_downloads.py -> reports/phase8g/registry.json
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from netsentinel.ledger import file_sha256, git_sha

ROOT = Path("data/raw/ctu13")
BASE = "https://mcfp.felk.cvut.cz/publicDatasets/"
# Content-Length from HEAD requests on 2026-10-28, before downloading
EXPECTED = {
    "CTU-Malware-Capture-Botnet-50/bro/conn.log": 338374507,
    "CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow":
        285841002,
    "CTU-Malware-Capture-Botnet-51/bro/conn.log": 1326633149,
    "CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow":
        179074339,
    "CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/"
    "capture20110818.binetflow.labeled": 192616246,
}  # fmt: skip
OUT = Path("reports/phase8g/registry.json")


def main() -> None:
    files = []
    for rel, size in EXPECTED.items():
        scen, name = rel.split("/")[0], rel.split("/")[-1]
        p = ROOT / scen / name
        got = p.stat().st_size if p.exists() else None
        files.append({"url": BASE + rel, "path": str(p).replace("\\", "/"), "expected_bytes": size,
                      "bytes": got, "size_ok": got == size,
                      "sha256": file_sha256(p) if p.exists() else None})  # fmt: skip
    reg = {"registration": "docs/phase8f/PREREG_CTU13.md", "dataset": "CTU-13 scenarios 9 and 10",
           "source": "official server mcfp.felk.cvut.cz (no mirrors)",
           "licence": "attribution only (accepted by the operator 2026-10-28)",
           "recorded_utc": datetime.now(UTC).isoformat(timespec="seconds"),
           "git_at_download": git_sha(), "files": files,
           "total_bytes": sum(f["bytes"] or 0 for f in files),
           "contents_opened": False,
           "frozen_evaluation_code_sha": None}  # fmt: skip
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(reg, indent=1), "utf-8")
    print(json.dumps({f["path"]: (f["bytes"], f["size_ok"], f["sha256"]) for f in files}, indent=1))


if __name__ == "__main__":
    main()
