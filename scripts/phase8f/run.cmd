@echo off
rem Phase 8f detached runner: %1 = script name under scripts\phase8f (without .py).
cd /d C:\Users\marke\projects\netsentinel-ai
set UV_CACHE_DIR=%USERPROFILE%\.uv\cache
set UV_PYTHON_INSTALL_DIR=%USERPROFILE%\.uv\python
set PYTHONIOENCODING=utf-8
echo start %1 %date% %time% > reports\phase8f\run.status
C:\Users\marke\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8f\%1.py > reports\phase8f\%1.log 2>&1
echo %1 exit %errorlevel% >> reports\phase8f\run.status
echo done %date% %time% >> reports\phase8f\run.status
