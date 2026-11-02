cd /c/Users/marke/projects/netsentinel-ai
export UV_CACHE_DIR=$USERPROFILE/.uv/cache UV_PYTHON_INSTALL_DIR=$USERPROFILE/.uv/python PYTHONIOENCODING=utf-8
UV=/c/Users/marke/.local/bin/uv.exe
SHA=$(git rev-parse --short HEAD)
for step in exp_a exp_b exp_c; do
  echo "dev $step start $(date -Is) $SHA" >> reports/phase8i/run.status
  $UV run python scripts/phase8i/$step.py > reports/phase8i/logs/$step.log 2>&1
  echo "dev $step exit $? $(date -Is)" >> reports/phase8i/run.status
done
