@echo off
REM ------------------------------------------------------------
REM  Launch the MasterInstaller PowerShell script
REM  (assumes MasterInstaller.ps1 is in the same directory)
REM ------------------------------------------------------------
"%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe" ^
    -NoLogo -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0MasterInstaller.ps1" %*

set "EXITCODE=%errorlevel%"
exit /b %EXITCODE%
