@echo off
REM ------------------------------------------------------------
REM  Launch the MasterInstaller PowerShell script
REM  (assumes MasterInstaller.ps1 is in the same directory)
REM ------------------------------------------------------------
"%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe" ^
    -NoLogo -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0MasterInstaller.ps1" %*

REM Keep the window open so you can read any output
pause
