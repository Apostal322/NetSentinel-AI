@echo off
rem Phase 8d post-hoc window rebuild (1.0M buffer cap), detached. Log in reports\phase8d\.
cd /d C:\Users\marke\projects\netsentinel-ai
set UV_CACHE_DIR=%USERPROFILE%\.uv\cache
set UV_PYTHON_INSTALL_DIR=%USERPROFILE%\.uv\python
echo start %date% %time% > reports\phase8d\run_all.status
C:\Users\marke\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8d\posthoc_windows.py > reports\phase8d\posthoc_windows.log 2>&1
echo posthoc_windows exit %errorlevel% >> reports\phase8d\run_all.status
echo done %date% %time% >> reports\phase8d\run_all.status
