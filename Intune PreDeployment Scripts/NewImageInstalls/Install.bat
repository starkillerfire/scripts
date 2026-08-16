@echo off
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -File "%~dp0NewImageInstalls.ps1"
set "EXITCODE=%errorlevel%"
exit /b %EXITCODE%