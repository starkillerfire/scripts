@echo off
cd /d "%~dp0"

echo ==============================
echo  Autopilot CSV Script
echo ==============================
echo.

powershell.exe -ExecutionPolicy Bypass -File "%~dp0Autopilot-v2.ps1"

pause