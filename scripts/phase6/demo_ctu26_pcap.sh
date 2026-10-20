#!/usr/bin/env bash
# Phase 6 real-traffic end-to-end demonstration, using only the product CLI.
# CTU-Normal-26 PCAP (benign, one host, 6.5 h; timestamps shifted to start near the epoch):
#   1. calibrate on flows ending before 03:15 (first half), vetted-benign (dataset provenance)
#   2. analyze flows ending at/after 03:15 with the calibration + application classifier
#   3. the same period without calibration (the Phase-5 configuration), for comparison
# Usage: bash scripts/phase6/demo_ctu26_pcap.sh models/appintel/<classifier-dir>
set -euo pipefail
PCAP=data/raw/ctu_normal_26/2017-04-28_normal.pcap
BUNDLE=models/bundle-20261019T202605Z
APPID="${1:?application classifier directory}"
CUT=1970-01-01T03:15:00
OUT=reports/phase6
mkdir -p "$OUT" artifacts
uv run netsentinel calibrate "$PCAP" --mode vetted_benign --assert-benign --until "$CUT" \
    --bundle "$BUNDLE" --out models/calibrations 2>"$OUT/ctu26_calibrate.log" | tee "$OUT/ctu26_calibrate.txt"
CAL=$(tail -n 1 "$OUT/ctu26_calibrate.txt")
uv run netsentinel analyze "$PCAP" --bundle "$BUNDLE" --calibration "$CAL" --appid "$APPID" \
    --since "$CUT" --events-db artifacts/ctu26_phase6.sqlite \
    --out "$OUT/ctu26_pcap_phase6.json" 2>"$OUT/ctu26_analyze.log"
uv run netsentinel analyze "$PCAP" --bundle "$BUNDLE" --since "$CUT" \
    --out "$OUT/ctu26_pcap_uncalibrated.json" 2>"$OUT/ctu26_analyze_uncal.log"
grep -h "peak_rss_mb" "$OUT"/ctu26_*.log || true
