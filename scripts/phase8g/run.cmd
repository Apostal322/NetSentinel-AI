@echo off
rem Phase 8g frozen CTU-13 run (docs/phase8f/PREREG_CTU13.md), detached; status in reports\phase8g\run.status.
cd /d C:\Users\marke\projects\netsentinel-ai
set UV_CACHE_DIR=%USERPROFILE%\.uv\cache
set UV_PYTHON_INSTALL_DIR=%USERPROFILE%\.uv\python
set PYTHONIOENCODING=utf-8
echo start %date% %time% > reports\phase8g\run.status
C:\Users\marke\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8g\windows.py scenario_9 > reports\phase8g\windows_9.log 2>&1
echo windows scenario_9 exit %errorlevel% >> reports\phase8g\run.status
C:\Users\marke\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8g\windows.py scenario_10 > reports\phase8g\windows_10.log 2>&1
echo windows scenario_10 exit %errorlevel% >> reports\phase8g\run.status
C:\Users\marke\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8g\evaluate.py > reports\phase8g\evaluate.log 2>&1
echo evaluate exit %errorlevel% >> reports\phase8g\run.status
echo done %date% %time% >> reports\phase8g\run.status
