#!/usr/bin/env bash
# Resumable download of the CSE-CIC-IDS2018 processed CSVs listed in the dataset manifest.
# Usage (from the repo root): bash scripts/download_ids2018.sh [dest_dir]
# Files whose size already matches the manifest are skipped; partial files are resumed.
# Then verify sizes and S3 multipart ETags: uv run netsentinel data verify
set -euo pipefail
manifest="configs/datasets/cse_cic_ids2018.yaml"
base=$(grep '^base_url:' "$manifest" | sed -E 's/^base_url: *"([^"]+)".*/\1/')
dest="${1:-data/raw/cse-cic-ids2018}"
mkdir -p "$dest"
grep -oE 'name: [A-Za-z0-9_-]+\.csv, day: "[^"]+", size: [0-9]+' "$manifest" \
  | sed -E 's/name: ([^,]+), day: "[^"]+", size: ([0-9]+)/\1 \2/' \
  | while read -r f size; do
      for attempt in 1 2 3 4 5 6 7 8 9 10; do
        have=$(stat -c %s "$dest/$f" 2>/dev/null || echo 0)
        if [ "$have" = "$size" ]; then echo "[$(date +%T)] ok $f"; break; fi
        echo "[$(date +%T)] fetch $f (have $have of $size, attempt $attempt)"
        curl --fail --retry 5 --retry-delay 10 -sS -C - -o "$dest/$f" "$base$f" || sleep 15
      done
      have=$(stat -c %s "$dest/$f" 2>/dev/null || echo 0)
      [ "$have" = "$size" ] || { echo "giving up on $f"; exit 1; }
    done
echo "[$(date +%T)] all downloads finished"
