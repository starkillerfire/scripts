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
