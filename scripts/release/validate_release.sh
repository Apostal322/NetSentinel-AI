#!/usr/bin/env bash
# Release validation from a FRESH CLONE (Phase 7 P4). Reproduces the CI `test` job locally and
# smoke-tests the installed application end to end. Model bundles are not in git, so a bundle
# directory must be supplied (BUNDLE=...). Docker is built only if it is installed.
#
# Usage: BUNDLE=/abs/path/models/bundle-<id> bash scripts/release/validate_release.sh [repo]
set -euo pipefail
SRC="${1:-$(git rev-parse --show-toplevel)}"
BUNDLE="${BUNDLE:?set BUNDLE to a model bundle directory}"
WORK="$(mktemp -d)"
LOG="$SRC/reports/phase7/release_validation.txt"
mkdir -p "$(dirname "$LOG")"
step() { printf '\n== %s\n' "$1" | tee -a "$LOG"; }
: > "$LOG"
echo "release validation $(date -u +%FT%TZ) commit $(git -C "$SRC" rev-parse --short HEAD)" | tee -a "$LOG"

step "fresh clone"
git clone -q "$SRC" "$WORK/ns"
cd "$WORK/ns"
git log --oneline -1 | tee -a "$LOG"

step "install from lockfile (base deps + dashboard extra, as CI)"
uv sync --locked --extra dashboard 2>&1 | tail -n 2 | tee -a "$LOG"

step "CI test job: ruff check / ruff format --check / pytest"
uv run --extra dashboard ruff check . 2>&1 | tail -n 1 | tee -a "$LOG"
uv run --extra dashboard ruff format --check . 2>&1 | tail -n 1 | tee -a "$LOG"
uv run --extra dashboard pytest -p no:warnings 2>&1 | tail -n 1 | tee -a "$LOG"

step "CLI"
uv run --extra dashboard netsentinel --help > /dev/null && echo "netsentinel --help ok" | tee -a "$LOG"
uv run --extra dashboard python scripts/make_demo_pcap.py "$WORK/demo.pcap" | tee -a "$LOG"

step "calibrate (synthetic capture; vetted mode) + registry"
uv run --extra dashboard netsentinel calibrate "$WORK/demo.pcap" --mode vetted_benign --assert-benign --window 5 \
    --out "$WORK/cal" --activate 2>/dev/null | tail -n 1 | tee -a "$LOG"
uv run --extra dashboard netsentinel calibration list --root "$WORK/cal" 2>/dev/null | head -n 3 | tee -a "$LOG"

step "analyze (PCAP) with bundle + calibration, default threat policy"
CAL="$(ls -d "$WORK"/cal/calibration-* | head -n 1)"
uv run --extra dashboard netsentinel analyze "$WORK/demo.pcap" --bundle "$BUNDLE" --calibration "$CAL" \
    --events-db "$WORK/events.sqlite" --out "$WORK/analyze.json" > /dev/null 2>&1
uv run --extra dashboard python - "$WORK/analyze.json" <<'PY' | tee -a "$LOG"
import json, sys
s = json.load(open(sys.argv[1]))
assert s["threat_mode"] == "unverified_domain", s["threat_mode"]
assert "suspicious" not in s["verdicts"] and "attack" not in s["verdicts"]
print("analyze ok:", s["flows"], "flows;", s["verdicts"], "| threat", s["threat_mode"])
PY

step "API server (real process) on 127.0.0.1:8765"
uv run --extra dashboard netsentinel serve --bundle "$BUNDLE" --port 8765 --events-db "$WORK/events.sqlite" \
    > "$WORK/serve.log" 2>&1 &
PID=$!
for _ in $(seq 1 60); do curl -fs http://127.0.0.1:8765/health > /dev/null 2>&1 && break; sleep 1; done
curl -fs http://127.0.0.1:8765/health | tee -a "$LOG"; echo | tee -a "$LOG"
curl -fs http://127.0.0.1:8765/ready | tee -a "$LOG"; echo | tee -a "$LOG"
curl -fs "http://127.0.0.1:8765/events?limit=1" > /dev/null && echo "/events ok" | tee -a "$LOG"
curl -fs -X POST http://127.0.0.1:8765/predict/flow -H 'content-type: application/json' \
    -d '{"timestamp":"2018-02-14T15:00:00","dst_port":22,"protocol":6,"flow_duration":1000,"features":{}}' \
    | uv run python -c "import json,sys; p=json.load(sys.stdin); assert p['threat_status']=='unverified_domain'; print('/predict/flow ok:', p['verdict'], p['threat_status'])" \
    | tee -a "$LOG"
kill "$PID" 2>/dev/null || true

step "docker"
if command -v docker > /dev/null 2>&1; then
    docker build -t netsentinel:release . 2>&1 | tail -n 3 | tee -a "$LOG"
else
    echo "BLOCKED: docker is not installed on this machine (image not built)" | tee -a "$LOG"
fi
echo "validation finished" | tee -a "$LOG"
