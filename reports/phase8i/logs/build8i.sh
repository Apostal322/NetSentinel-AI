cd /c/Users/marke/projects/netsentinel-ai
export UV_CACHE_DIR=$USERPROFILE/.uv/cache UV_PYTHON_INSTALL_DIR=$USERPROFILE/.uv/python PYTHONIOENCODING=utf-8
UV=/c/Users/marke/.local/bin/uv.exe
for net in nfcic nfton; do
  echo "build $net $(date -Is)" >> reports/phase8i/run.status
  $UV run python scripts/phase8i/build_windows.py $net > reports/phase8i/logs/build_$net.log 2>&1
  echo "build $net exit $? $(date -Is)" >> reports/phase8i/run.status
done
