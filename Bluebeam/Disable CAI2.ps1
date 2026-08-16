<# 
.SYNOPSIS
  Disables Microsoft-Windows-CAPI2/Operational logging.

.DESCRIPTION
  Simple helper for end users: turns off verbose CAPI2 diagnostics
  once Bluebeam / TSA testing is complete.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Require Administrator ---------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERR] This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and choose 'Run as administrator'."
    exit 1
}

try {
    # wevtutil.exe is a native command - a nonzero exit code doesn't raise a
    # terminating PowerShell error, so try/catch alone never caught a real
    # failure here, and the script always exited 0 regardless of outcome -
    # which matters if this is ever wired up as an Intune detection/
    # remediation script.
    wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:false
    if ($LASTEXITCODE -ne 0) { throw "wevtutil exited $LASTEXITCODE" }
    Write-Host "[ OK ] CAPI2 logging is now DISABLED." -ForegroundColor Green
} catch {
    Write-Host "[ERR] Failed to disable CAPI2: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
