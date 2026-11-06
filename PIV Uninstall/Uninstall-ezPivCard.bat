REM BEGIN SCRIPT LIBRARY REMOTE UPDATE
@echo off
set "SCRIPT_LIBRARY_ACTIVE_LAUNCHER=%~f0"
REM Apply a staged update before CMD reads the rest of this launcher.
if exist "%~f0.update.pending" (
    powershell.exe -NoProfile -NonInteractive -Command "try { $p=$env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER; $c=Join-Path (Split-Path $p -Parent) 'Uninstall-ezPivCard.ps1'; $s=Get-AuthenticodeSignature -LiteralPath $c -ErrorAction Stop; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315'){throw 'Approved companion signature required.'}; & $c -LibraryPendingBatch $p; exit $LASTEXITCODE } catch { Write-Error $_; exit 1 }"
    if errorlevel 1 exit /b 1
    call "%~f0" %*
    call exit /b %%errorlevel%%
)
REM END SCRIPT LIBRARY REMOTE UPDATE
@echo off
REM ================================================================
REM General About Section
REM ================================================================
REM Launcher for Uninstall-ezPivCard.ps1.
REM Selects the correct PowerShell host, self-elevates if not already
REM running as administrator, and passes the exit code back to the
REM calling process (SCCM, Intune, or local interactive run).
REM
REM Author:     OCIO SCCM Team
REM Revision:   08/17/2015 - Initial build
REM             07/07/2016 - Removed parameter support
REM             2026-06-23 - Full rewrite: self-elevation; clean
REM                          variable scope; quoted set syntax;
REM                          PROCESSOR_ARCHITEW6432 arch detection;
REM                          %PWSH% variable; -NonInteractive flag;
REM                          RemoteSigned policy; pre-flight checks;
REM                          errorlevel capture before echo/pause;
REM                          pause for interactive use;
REM                          %* argument passthrough to PS1.
REM ================================================================

REM ================================================================
REM DO NOT EDIT BELOW THIS LINE
REM ================================================================

setlocal enableextensions enabledelayedexpansion

REM Quoted set syntax (set "var=val") prevents trailing spaces from
REM being silently captured in the variable value.
REM Variables are inside setlocal so they cannot leak to a parent process.
set "ScriptFile=Uninstall-ezPivCard.ps1"
set "LogDir=C:\SoftwareLogs"

REM ----------------------------------------------------------------
REM Self-elevation
REM ----------------------------------------------------------------
REM Check whether this session already has administrator rights.
REM "net session" succeeds (errorlevel 0) only when running as admin.
REM If not elevated, re-launch this BAT file elevated via PowerShell's
REM Start-Process -Verb RunAs, which triggers a UAC prompt.
REM
REM NOTE: The exit code from the elevated window cannot be propagated
REM       back to the non-elevated caller (OS security boundary).
REM       The result is visible in the elevated window, which stays
REM       open until the user presses a key (see "pause" below).
REM ----------------------------------------------------------------
net session >nul 2>&1
if !errorlevel! neq 0 (
    REM A single quote in a forwarded argument would close the single-quoted
    REM -ArgumentList string below early and run as independent PowerShell
    REM code in this non-elevated process, before elevation even happens.
    REM Reject any such argument outright rather than trying to escape it.
    echo(%*| findstr /C:"'" >nul
    if !errorlevel! equ 0 (
        echo [ERROR] Arguments contain an illegal single-quote character and were rejected.
        exit /b 1
    )

    echo [INFO] Administrator rights required. Requesting elevation...
    powershell -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c \"\"%~f0\"\" %*' -Verb RunAs -Wait"
    echo [INFO] Elevated session finished. Check the elevated window for results.
    exit /b 0
)

REM ----------------------------------------------------------------
REM Pre-flight checks
REM ----------------------------------------------------------------

REM Create the log directory; abort with a clear message on failure.
if not exist "%LogDir%" (
    md "%LogDir%"
    if !errorlevel! neq 0 (
        echo [ERROR] Could not create log directory: %LogDir%
        exit /b 1
    )
)

REM Abort early with a clear message if the PS1 is missing.
if not exist "%~dp0%ScriptFile%" (
    echo [ERROR] Script not found: %~dp0%ScriptFile%
    exit /b 1
)

REM ----------------------------------------------------------------
REM PowerShell host selection
REM ----------------------------------------------------------------
REM PROCESSOR_ARCHITEW6432 is only defined when a 32-bit cmd.exe is
REM running on a 64-bit OS (WOW64). In that case sysnative is needed
REM to reach the real 64-bit powershell.exe. Otherwise system32.
if defined PROCESSOR_ARCHITEW6432 (
    set "PWSH=%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe"
) else (
    set "PWSH=%windir%\system32\WindowsPowerShell\v1.0\powershell.exe"
)

REM %* passes any arguments supplied to this BAT straight through to the PS1.
REM Example: Uninstall-ezPivCard.bat -DryRun
REM
REM NOTE: -NonInteractive is intentionally NOT passed here. The PS1's own
REM defaults ($showUI/$confirmEachUninstall/$rebootPromptEnabled = $true)
REM call Read-Host for local interactive use, and -NonInteractive makes any
REM Read-Host call throw instead of prompting - so it would crash the
REM script on its own default configuration. Unattended callers (SCCM/
REM Intune) should pass -Silent, which already disables every Read-Host
REM path in the PS1 (they're all gated on $showUI), making -NonInteractive
REM unnecessary for them too.
%PWSH% -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0%ScriptFile%" %*

REM ----------------------------------------------------------------
REM Exit handling
REM ----------------------------------------------------------------
REM Save errorlevel immediately - echo and pause both reset it to 0,
REM so it must be captured before any output or prompting.
set EXITCODE=!errorlevel!
if !EXITCODE! neq 0 echo [ERROR] Script exited with code !EXITCODE!

REM Skip the pause for unattended/silent invocations (SCCM/Intune, or any
REM caller passing -Silent through to the PS1) - there is no console under
REM SYSTEM, so an unconditional pause here would hang until Intune's
REM timeout marks an otherwise-successful run as failed.
set "ARGS=%*"
echo(!ARGS!| findstr /I /C:"-Silent" >nul
if !errorlevel! equ 0 goto :SkipPause

REM Keeps the window open so results are visible after this interactive run.
pause

:SkipPause
exit /b !EXITCODE!
