@echo off
setlocal enabledelayedexpansion
title LogHawk - CLI
pushd "%~dp0"

REM ---------------------------------------------------------------
REM  Find a Python. Prefer the project's virtual environment if one
REM  exists, but the detection engine is pure standard library, so a
REM  plain system Python runs every command in this file.
REM ---------------------------------------------------------------
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if defined PY goto :got_python

py -3 --version >nul 2>&1
if %errorlevel%==0 set "PY=py -3"
if defined PY goto :got_python

python --version >nul 2>&1
if %errorlevel%==0 set "PY=python"
if defined PY goto :got_python

goto :no_python

:got_python

REM ---------------------------------------------------------------
REM  Arguments given?  Pass them straight through.
REM      loghawk.bat scan C:\logs --min-severity high --verbose
REM ---------------------------------------------------------------
if not "%~1"=="" (
    %PY% -m loghawk %*
    goto :finish
)

REM ---------------------------------------------------------------
REM  No arguments - show a menu, so double-clicking does something
REM  useful instead of flashing a window and closing.
REM ---------------------------------------------------------------
:menu
cls
echo.
echo   ==========================================================
echo     L O G H A W K   -   blue-team log detection engine
echo   ==========================================================
echo.
echo     1.  Run the demo          ^(sample intrusion, full report^)
echo     2.  Scan the samples      ^(critical findings only^)
echo     3.  List the 10 detection rules
echo     4.  Export a Markdown incident report
echo     5.  Scan a folder of my own logs
echo     6.  Show all command-line options
echo.
echo     0.  Exit
echo.
set "choice="
set /p "choice=   Choose an option: "

if "%choice%"=="1" goto :opt_demo
if "%choice%"=="2" goto :opt_crit
if "%choice%"=="3" goto :opt_rules
if "%choice%"=="4" goto :opt_report
if "%choice%"=="5" goto :opt_custom
if "%choice%"=="6" goto :opt_help
if "%choice%"=="0" goto :finish
goto :menu

:opt_demo
cls
%PY% -m loghawk demo --verbose
goto :again

:opt_crit
cls
%PY% -m loghawk scan samples --year 2026 --min-severity critical --verbose
goto :again

:opt_rules
cls
%PY% -m loghawk rules
goto :again

:opt_report
cls
%PY% -m loghawk scan samples --year 2026 --format markdown --output incident-report.md
echo.
echo   Saved as incident-report.md next to this file.
goto :again

:opt_custom
cls
echo.
echo   Enter the full path to a log file or a folder of logs.
echo   Example:  C:\Users\Abdullah\Desktop\logs
echo.
set "target="
set /p "target=   Path: "
if "%target%"=="" goto :menu
if not exist "%target%" (
    echo.
    echo   That path does not exist.
    goto :again
)
cls
%PY% -m loghawk scan "%target%" --verbose
goto :again

:opt_help
cls
%PY% -m loghawk --help
echo.
%PY% -m loghawk scan --help
goto :again

:again
echo.
echo   ----------------------------------------------------------
set "back="
set /p "back=   Press ENTER for the menu, or type Q to quit: "
if /i "%back%"=="Q" goto :finish
goto :menu

:no_python
color 0C
echo.
echo   Python is not installed on this machine ^(or not on PATH^).
echo.
echo   Fix it in three steps:
echo     1. Download Python 3.10 or newer from  https://www.python.org/downloads/
echo     2. In the installer, TICK "Add python.exe to PATH" on the first screen.
echo     3. Close this window, open a NEW one, and run this file again.
echo.
popd
pause
exit /b 1

:finish
popd
REM Pause only when launched by double-click, not from an open terminal.
echo %cmdcmdline% | find /i "%~nx0" >nul
if not errorlevel 1 pause
exit /b 0
