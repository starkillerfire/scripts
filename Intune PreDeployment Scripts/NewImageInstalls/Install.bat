REM BEGIN SCRIPT LIBRARY REMOTE UPDATE
@echo off
set "SCRIPT_LIBRARY_ACTIVE_LAUNCHER=%~f0"
REM Apply a staged update before CMD reads the rest of this launcher.
if exist "%~f0.update.pending" (
    powershell.exe -NoProfile -NonInteractive -Command "try { $p=$env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER; $c=Join-Path (Split-Path $p -Parent) 'NewImageInstalls.ps1'; $s=Get-AuthenticodeSignature -LiteralPath $c -ErrorAction Stop; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315'){throw 'Approved companion signature required.'}; & $c -LibraryPendingBatch $p; exit $LASTEXITCODE } catch { Write-Error $_; exit 1 }"
    if errorlevel 1 exit /b 1
    call "%~f0" %*
    call exit /b %%errorlevel%%
)
REM END SCRIPT LIBRARY REMOTE UPDATE
@echo off
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -File "%~dp0NewImageInstalls.ps1"
set "EXITCODE=%errorlevel%"
exit /b %EXITCODE%