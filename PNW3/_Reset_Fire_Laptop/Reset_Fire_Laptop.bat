REM BEGIN SCRIPT LIBRARY REMOTE UPDATE
@echo off
set "SCRIPT_LIBRARY_ACTIVE_LAUNCHER=%~f0"
REM Apply a staged update before CMD reads the rest of this launcher.
if exist "%~f0.update.pending" (
    powershell.exe -NoProfile -NonInteractive -Command "try { $p=$env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER; $c=Join-Path (Split-Path $p -Parent) 'Reset_Fire_Laptop.ps1'; $s=Get-AuthenticodeSignature -LiteralPath $c -ErrorAction Stop; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315'){throw 'Approved companion signature required.'}; & $c -LibraryPendingBatch $p; exit $LASTEXITCODE } catch { Write-Error $_; exit 1 }"
    if errorlevel 1 exit /b 1
    call "%~f0" %*
    call exit /b %%errorlevel%%
)
REM END SCRIPT LIBRARY REMOTE UPDATE
@ECHO OFF
REM Reset_Fire_Laptop.ps1 self-elevates via UAC on its own (see its
REM #region Admin check / self-elevate) using $PSBoundParameters, which
REM handles quoting/argument forwarding correctly. This launcher used to
REM duplicate that elevation itself via a hand-built -ArgumentList string,
REM but cmd.exe's quoting rules for %* broke that string the moment any
REM argument was forwarded, silently preventing the script from launching
REM at all - so this now just hands off to the script unelevated and lets
REM its own already-tested elevation logic take over.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dpn0.ps1" %*
