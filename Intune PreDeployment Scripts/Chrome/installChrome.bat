@echo off
cd /d "%~dp0"

powershell.exe -ExecutionPolicy Bypass -File "%~dp0installChrome.ps1"
set "EXITCODE=%errorlevel%"
exit /b %EXITCODE%