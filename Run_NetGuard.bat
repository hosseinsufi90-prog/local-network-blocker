@echo off
:: NetGuard launcher - double-click this file to start the app.
:: It automatically asks for Administrator rights (needed by scapy)
:: and then runs gui_app.py from this same folder.

:: Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Requesting administrator rights...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0"
python gui_app.py
pause
