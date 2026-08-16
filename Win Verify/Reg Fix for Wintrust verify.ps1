#Requires -Version 5.1
<#
.SYNOPSIS
    Enable WinVerifyTrust signature hardening (CVE-2013-3900) on local or remote computers.

.DESCRIPTION
    Sets EnableCertPaddingCheck = 1 (DWORD) in both the 64-bit and WOW6432Node Wintrust
    registry paths. Uses the .NET remote registry API (DCOM/RPC) for remote targets -
    no WinRM required.

.PARAMETER ComputerName
    Single target computer. Omit to target the local machine.

.PARAMETER CsvPath
    CSV file with a "SystemName" column for bulk targeting.

.PARAMETER OutputCsv
    Path for the per-machine results CSV. Defaults to results.csv beside this script.

.EXAMPLE
    .\Reg Fix for Wintrust verify.ps1
    Apply to the local machine only.

.EXAMPLE
    .\Reg Fix for Wintrust verify.ps1 -CsvPath .\systems.csv -OutputCsv .\results.csv
#>
# SupportsShouldProcess added so -WhatIf/-Confirm work here like they do
# elsewhere in the repo, given this writes a registry value fleet-wide.
# ConfirmImpact 'Medium' (below the default $ConfirmPreference of 'High') so
# it doesn't auto-prompt-and-hang under a non-interactive/bulk CSV run.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string] $ComputerName,
    [string] $CsvPath,
    [string] $OutputCsv = (Join-Path $PSScriptRoot 'results.csv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$keyName  = 'EnableCertPaddingCheck'
$keyValue = 1

# Both 64-bit and WOW6432Node paths must be set (CVE-2013-3900 affects both)
$subKeyPaths = @(
    'SOFTWARE\Microsoft\Cryptography\Wintrust\Config',
    'SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'
)

function Set-WinVerifyTrustLocal {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    foreach ($subKey in $subKeyPaths) {
        if (-not $PSCmdlet.ShouldProcess("HKLM:\$subKey", "Set $keyName = $keyValue")) { continue }
        $psPath = "HKLM:\$subKey"
        if (-not (Test-Path $psPath)) { New-Item -Path $psPath -Force | Out-Null }
        Set-ItemProperty -Path $psPath -Name $keyName -Value $keyValue -Type DWord -Force
    }
}

function Set-WinVerifyTrustRemote {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$Target)
    $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, $Target)
    try {
        foreach ($subKey in $subKeyPaths) {
            if (-not $PSCmdlet.ShouldProcess("$Target\HKLM:\$subKey", "Set $keyName = $keyValue")) { continue }
            $key = $remoteReg.OpenSubKey($subKey, $true)
            if (-not $key) { $key = $remoteReg.CreateSubKey($subKey) }
            $key.SetValue($keyName, $keyValue, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.Close()
        }
    } finally {
        $remoteReg.Close()
    }
}

function Invoke-Hardening {
    param([string]$Target)
    $isLocal = (-not $Target) -or ($Target -eq 'localhost') -or ($Target -eq $env:COMPUTERNAME)
    try {
        if ($isLocal) {
            Set-WinVerifyTrustLocal
        } else {
            Set-WinVerifyTrustRemote -Target $Target
        }
        $label = if ($isLocal) { $env:COMPUTERNAME } else { $Target }
        Write-Host "[$label] Hardening applied." -ForegroundColor Green
        return [PSCustomObject]@{ System = $label; Status = 'Success'; Error = '' }
    } catch {
        $label = if ($isLocal) { $env:COMPUTERNAME } else { $Target }
        Write-Warning "[$label] Failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ System = $label; Status = 'Failed'; Error = $_.Exception.Message }
    }
}

# --- Build target list ---
$targets = [System.Collections.Generic.List[string]]::new()
if ($ComputerName)                   { $targets.Add($ComputerName) }
if ($CsvPath -and (Test-Path $CsvPath)) { (Import-Csv -Path $CsvPath).SystemName | ForEach-Object { $targets.Add($_) } }
if ($targets.Count -eq 0)            { $targets.Add('localhost') }

$results = foreach ($t in $targets) { Invoke-Hardening -Target $t }

$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
Write-Host "Results saved to: $OutputCsv"

$failed = @($results | Where-Object { $_.Status -eq 'Failed' })
if ($failed.Count) { Write-Warning "$($failed.Count) machine(s) failed. Check $OutputCsv for details." }

exit ($(if ($failed.Count -gt 0) { 1 } else { 0 }))
