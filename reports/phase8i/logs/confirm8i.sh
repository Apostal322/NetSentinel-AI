cd /c/Users/marke/projects/netsentinel-ai
export UV_CACHE_DIR=$USERPROFILE/.uv/cache UV_PYTHON_INSTALL_DIR=$USERPROFILE/.uv/python PYTHONIOENCODING=utf-8
UV=/c/Users/marke/.local/bin/uv.exe
SHA=$(git rev-parse --short HEAD)
step() { echo "confirm $1 start $(date -Is) $SHA" >> reports/phase8i/run.status; shift_name=$1; shift; "$@" > reports/phase8i/logs/confirm_$shift_name.log 2>&1; rc=$?; echo "confirm $shift_name exit $rc $(date -Is)" >> reports/phase8i/run.status; return $rc; }
step ingest $UV run python -c "import sys; from netsentinel.cli import main; sys.exit(main(['data','ingest-nf','nf-bot-iot-v3']))" || exit 1
step build $UV run python scripts/phase8i/build_windows.py nfbot --protected-confirm || exit 1
step exp_a $UV run python scripts/phase8i/exp_a.py --confirm --out reports/phase8i/confirm/exp_a || exit 1
step exp_c $UV run python scripts/phase8i/exp_c.py --confirm --part cross --out reports/phase8i/confirm/exp_c || exit 1
step exp_b $UV run python scripts/phase8i/exp_b.py --confirm --tau 0.7009482465833334 --out reports/phase8i/confirm/exp_b || exit 1
step verdicts $UV run python scripts/phase8i/confirm_analyze.py
