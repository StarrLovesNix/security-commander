@echo off
:: Security Commander — Windows Setup Launcher
:: Automatically requests UAC elevation if not already running as Administrator.

title Security Commander Setup

:: Check for administrator privileges
net session >nul 2>&1
if %errorLevel% equ 0 (
    goto :run_setup
)

:: Not elevated — re-launch this script with UAC elevation via PowerShell
echo Requesting administrator privileges...
powershell -NoProfile -Command ^
    "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
exit /b %errorLevel%

:run_setup
cd /d "%~dp0"

:: Verify Python is available
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python was not found on PATH.
    echo.
    echo Please install Python 3.10 or newer from https://python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Show Python version for confirmation
echo Python found:
python --version
echo.

:: Run the setup wizard
python "%~dp0setup.py" %*
set EXIT_CODE=%errorLevel%

echo.
pause
exit /b %EXIT_CODE%
