@echo off
:: Universal Print — Client Printer Cleanup Launcher
:: Double-click this file to run the cleanup tool.
:: The script will automatically request Administrator privileges via UAC.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Remove-UPPrinterFromClient.ps1"
