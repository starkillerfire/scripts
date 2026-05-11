#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remote Edge silent installation via robocopy + PsExec.

.PARAMETER ComputerName
    Single target computer name.

.PARAMETER CsvPath
    CSV file with a "ComputerName" column.

.PARAMETER SourcePath
    UNC or local path containing the Edge MSI. No default — must be supplied.

.PARAMETER PsExecPath
    Path to PsExec.exe. Defaults to psexec.exe in the same folder as this script.

.PARAMETER MsiName
    MSI filename in SourcePath. Defaults to MicrosoftEdgeEnterpriseX64.msi.

.PARAMETER TempDirName
    Name of the staging folder created under C:\ on each remote machine. Defaults to TempEdge.

.EXAMPLE
    .\EdgeInstall23.ps1 -CsvPath C:\computers.csv -SourcePath \\fileserver\patches\Edge
    .\EdgeInstall23.ps1 -ComputerName PC001 -SourcePath \\fileserver\patches\Edge -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ComputerName,
    [string] $CsvPath,
    [Parameter(Mandatory)]
    [string] $SourcePath,
    [string] $PsExecPath  = (Join-Path $PSScriptRoot 'psexec.exe'),
    [string] $MsiName     = 'MicrosoftEdgeEnterpriseX64.msi',
    [string] $TempDirName = 'TempEdge'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Build computer list ---
$computers = [System.Collections.Generic.List[string]]::new()
if ($ComputerName) { $computers.Add($ComputerName) }
if ($CsvPath)      { (Import-Csv -Path $CsvPath).ComputerName | ForEach-Object { $computers.Add($_) } }
if ($computers.Count -eq 0) { throw 'Provide -ComputerName or -CsvPath.' }

# --- Preflight checks ---
if (-not (Test-Path $PsExecPath)) { throw "PsExec not found: $PsExecPath" }
if (-not (Test-Path $SourcePath)) { throw "Source path not found: $SourcePath" }
$msiFullPath = Join-Path $SourcePath $MsiName
if (-not (Test-Path $msiFullPath)) { throw "MSI not found at: $msiFullPath" }

$succeeded = [System.Collections.Generic.List[string]]::new()
$failed    = [System.Collections.Generic.List[string]]::new()

foreach ($computer in $computers) {
    $uncTemp   = "\\$computer\c$\$TempDirName"
    $remoteMsi = "C:\$TempDirName\$MsiName"

    Write-Host "[$computer] Starting Edge install..."

    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
        Write-Warning "[$computer] Not reachable — skipping."
        $failed.Add($computer)
        continue
    }

    try {
        New-Item -Path $uncTemp -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

        robocopy $SourcePath $uncTemp /mir /R:2 /W:2 | Out-Null
        if ($LASTEXITCODE -ge 8) {
            Write-Warning "[$computer] Robocopy failed (exit $LASTEXITCODE) — skipping."
            $failed.Add($computer)
            continue
        }

        if ($PSCmdlet.ShouldProcess($computer, 'Install Edge via msiexec')) {
            & $PsExecPath "\\$computer" -s -accepteula cmd /c "msiexec.exe /I `"$remoteMsi`" /qn /norestart" 2>$null
            $rc = $LASTEXITCODE
            if ($rc -in @(0, 3010)) {
                Write-Host "[$computer] Edge installed successfully (exit $rc)." -ForegroundColor Green
                $succeeded.Add($computer)
            } else {
                Write-Warning "[$computer] msiexec returned exit code $rc."
                $failed.Add($computer)
            }
        }
    } catch {
        Write-Warning "[$computer] Unexpected error: $_"
        $failed.Add($computer)
    } finally {
        Remove-Item -Path $uncTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Summary: $($succeeded.Count) succeeded, $($failed.Count) failed."
if ($failed.Count -gt 0) {
    Write-Warning "Failed machines: $($failed -join ', ')"
}
