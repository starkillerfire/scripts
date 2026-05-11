@echo off
cd /d "%~dp0"
powershell Set-ExecutionPolicy Bypass -Force
powershell.exe -file "%~dp0NewImageInstalls.ps1"
pause