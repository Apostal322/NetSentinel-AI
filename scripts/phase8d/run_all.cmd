@echo off
rem Phase 8d analyses, sequential (one heavy job at a time). Logs in reports\phase8d\.
cd /d C:\Users\marke\projects\netsentinel-ai
set UV=C:\Users\marke\.local\bin\uv.exe
set UV_CACHE_DIR=%USERPROFILE%\.uv\cache
set UV_PYTHON_INSTALL_DIR=%USERPROFILE%\.uv\python
echo start %date% %time% > reports\phase8d\run_all.status
%UV% run --extra torch python -W ignore scripts\phase8d\posthoc_windows.py > reports\phase8d\posthoc_windows.log 2>&1
echo posthoc_windows exit %errorlevel% >> reports\phase8d\run_all.status
%UV% run --extra torch python -W ignore scripts\phase8d\operating_points.py > reports\phase8d\operating_points.log 2>&1
echo operating_points exit %errorlevel% >> reports\phase8d\run_all.status
%UV% run --extra torch python -W ignore scripts\phase8d\drift_gaps.py > reports\phase8d\drift_gaps.log 2>&1
echo drift_gaps exit %errorlevel% >> reports\phase8d\run_all.status
%UV% run --extra torch python -W ignore scripts\phase8d\ci_reliability.py > reports\phase8d\ci_reliability.log 2>&1
echo ci_reliability exit %errorlevel% >> reports\phase8d\run_all.status
echo done %date% %time% >> reports\phase8d\run_all.status
