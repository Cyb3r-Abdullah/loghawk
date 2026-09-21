@echo off
setlocal enabledelayedexpansion
title LogHawk - SOC Dashboard
pushd "%~dp0"
color 0B

echo.
echo   ==========================================================
echo     L O G H A W K   -   starting the SOC dashboard
echo   ==========================================================
echo.

REM ---------------------------------------------------------------
REM  1. Find a working Python.
REM     The "py" launcher is tried first because on Windows a bare
REM     "python" is often the Microsoft Store stub, which is not a
REM     real interpreter and exits with an error.
REM ---------------------------------------------------------------
set "PY="
py -3 --version >nul 2>&1
if %errorlevel%==0 set "PY=py -3"
if defined PY goto :got_python

python --version >nul 2>&1
if %errorlevel%==0 set "PY=python"
if defined PY goto :got_python

goto :no_python

:got_python
for /f "tokens=*" %%v in ('%PY% --version 2^>^&1') do set "PYVER=%%v"
echo   Python found: !PYVER!
echo.

REM ---------------------------------------------------------------
REM  2. Create a virtual environment the first time only.
REM ---------------------------------------------------------------
if exist ".venv\Scripts\python.exe" goto :have_venv
echo   [1/4] First run - creating a virtual environment in .venv ...
%PY% -m venv .venv
if errorlevel 1 goto :venv_failed
echo         done.
echo.

:have_venv
set "VPY=.venv\Scripts\python.exe"

REM ---------------------------------------------------------------
REM  3. Install FastAPI + uvicorn only if they are missing.
REM     The detection engine itself needs nothing but the stdlib.
REM ---------------------------------------------------------------
"%VPY%" -c "import fastapi, uvicorn" >nul 2>&1
if %errorlevel%==0 goto :have_deps
echo   [2/4] Installing dashboard dependencies ^(one time, ~30s^) ...
"%VPY%" -m pip install --upgrade pip --quiet --disable-pip-version-check
"%VPY%" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 goto :pip_failed
echo         done.
echo.

:have_deps

REM ---------------------------------------------------------------
REM  4. Seed the database on first run so the dashboard is not empty.
REM ---------------------------------------------------------------
if exist "loghawk.db" goto :have_db
echo   [3/4] No database yet - scanning the bundled sample logs ...
"%VPY%" -m loghawk scan samples --year 2026 --db loghawk.db --format csv >nul
if errorlevel 1 goto :scan_failed
echo         done.
echo.

:have_db

REM ---------------------------------------------------------------
REM  5. Open the browser a few seconds from now, then serve.
REM ---------------------------------------------------------------
echo   [4/4] Starting the server ...
echo.
echo   ----------------------------------------------------------
echo     Dashboard   http://127.0.0.1:8000/
echo     API docs    http://127.0.0.1:8000/docs
echo.
echo     Press Ctrl+C in this window to stop the server.
echo   ----------------------------------------------------------
echo.

start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://127.0.0.1:8000/'" >nul 2>&1

"%VPY%" -m loghawk serve --host 127.0.0.1 --port 8000 --db loghawk.db

echo.
echo   Server stopped.
popd
pause
exit /b 0

REM ===============================================================
REM  Failure paths
REM ===============================================================
:no_python
color 0C
echo   Python is not installed on this machine ^(or not on PATH^).
echo.
echo   Fix it in three steps:
echo     1. Download Python 3.10 or newer from  https://www.python.org/downloads/
echo     2. In the installer, TICK "Add python.exe to PATH" on the first screen.
echo        This is the step people skip, and it causes exactly this error.
echo     3. Close this window, open a NEW one, and run this file again.
echo.
echo   Note: if a "Python was not found ... Microsoft Store" message appeared
echo   earlier, that was a Windows placeholder, not a real Python.
echo.
popd
pause
exit /b 1

:venv_failed
color 0C
echo.
echo   Could not create the virtual environment.
echo   Try deleting the .venv folder and running this file again.
popd
pause
exit /b 1

:pip_failed
color 0C
echo.
echo   Dependency installation failed - usually a network or proxy issue.
echo   You can retry manually with:
echo       .venv\Scripts\python.exe -m pip install -r requirements.txt
popd
pause
exit /b 1

:scan_failed
color 0C
echo.
echo   The initial scan failed. Check that the "samples" folder is present
echo   next to this file, then run it again.
popd
pause
exit /b 1
