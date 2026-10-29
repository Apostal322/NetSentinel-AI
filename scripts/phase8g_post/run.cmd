@echo off
rem Phase 8g post-hoc audit [R]: runs the steps listed in %1, one process at a time, detached;
rem status in reports\phase8g_post\run.status. A line is either stream_audit.py arguments or
rem "script <path>" for another script of this directory.
setlocal enabledelayedexpansion
cd /d %~dp0..\..
set UV_CACHE_DIR=%USERPROFILE%\.uv\cache
set UV_PYTHON_INSTALL_DIR=%USERPROFILE%\.uv\python
set PYTHONIOENCODING=utf-8
if not exist reports\phase8g_post\logs mkdir reports\phase8g_post\logs
echo start %date% %time% > reports\phase8g_post\run.status
set n=0
for /f "usebackq tokens=1,* delims= " %%a in ("%~1") do (
  set /a n+=1
  echo begin !n! %%a %%b !time! >> reports\phase8g_post\run.status
  if "%%a"=="script" (
    %USERPROFILE%\.local\bin\uv.exe run --extra torch python -W ignore %%b > reports\phase8g_post\logs\%~n1_!n!.log 2>&1
  ) else (
    %USERPROFILE%\.local\bin\uv.exe run --extra torch python -W ignore scripts\phase8g_post\stream_audit.py %%a %%b > reports\phase8g_post\logs\%~n1_!n!.log 2>&1
  )
  echo end !n! exit !errorlevel! !time! >> reports\phase8g_post\run.status
)
echo done %date% %time% >> reports\phase8g_post\run.status
