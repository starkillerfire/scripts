#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # speeds up Invoke-WebRequest downloads

# Set by the Install-* functions below when an msiexec/installer exit code
# of 3010 or 1641 (success, reboot required) is seen, so the final exit code
# can reflect it instead of collapsing every non-hard-failure outcome to 0.
$script:AnyRebootNeeded = $false

function Test-DownloadedInstallerSignature {
    <#
    .SYNOPSIS
        Verifies a downloaded installer is validly signed by the expected
        publisher before it gets executed - none of the four downloads in
        this script (Chrome MSI, Edge MSI, .NET runtime EXE, DCU EXE) had
        any integrity check before, unlike the sibling install scripts in
        this repo.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSignerPattern
    )
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch $ExpectedSignerPattern) {
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        throw "Downloaded installer at $Path failed Authenticode validation (status: $($sig.Status)) - refusing to run it."
    }
}

# Chrome and Edge both used to reimplement their own download+install logic
# here, duplicating (and drifting from) installChrome.ps1/Edge.ps1 elsewhere
# in the repo - both now just call the consolidated
# ..\Browsers\Install-Browsers.ps1, which those two were themselves replaced
# by (see Browser Install Archive\README.md).
function Invoke-BrowserInstaller {
    param([Parameter(Mandatory)][ValidateSet('Chrome', 'Edge')][string]$Browser)
    $installerPath = Join-Path $PSScriptRoot '..\Browsers\Install-Browsers.ps1'
    if (-not (Test-Path $installerPath)) {
        Write-Output "Browser installer script not found: $installerPath"
        return $false
    }
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installerPath -Browser $Browser
    switch ($LASTEXITCODE) {
        0       { return $true }
        3010    { $script:AnyRebootNeeded = $true; return $true }
        1641    { $script:AnyRebootNeeded = $true; return $true }
        default { Write-Output "Browser installer exited with code $LASTEXITCODE"; return $false }
    }
}

function Install-Chrome {
    Write-Output ""
    Write-Output "Installing Google Chrome..."
    return Invoke-BrowserInstaller -Browser Chrome
}

function Install-Edge {
    Write-Output ""
    Write-Output "Installing Microsoft Edge..."
    return Invoke-BrowserInstaller -Browser Edge
}

function Install-DotNet {
    Write-Output ""
    Write-Output "Installing .NET Desktop Runtime 8.0.x..."
    try {
        winget install Microsoft.DotNet.DesktopRuntime.8 -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -ne 0) { throw "winget exited $LASTEXITCODE" }
        return $true
    } catch {
        try {
            $uri  = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/8.0.18/windowsdesktop-runtime-8.0.18-win-x64.exe"
            $path = "$PSScriptRoot\windowsdesktop-runtime-8.0.18-win-x64.exe"
            Invoke-WebRequest -Uri $uri -OutFile $path -UseBasicParsing -ErrorAction Stop
            Test-DownloadedInstallerSignature -Path $path -ExpectedSignerPattern 'O=Microsoft Corporation'
            $proc = Start-Process -Wait -FilePath $path -ArgumentList '/install','/quiet','/norestart' -PassThru
            if ($proc.ExitCode -notin @(0, 3010)) { throw "Installer exited $($proc.ExitCode)" }
            if ($proc.ExitCode -eq 3010) { $script:AnyRebootNeeded = $true }
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
            return $true
        } catch {
            Write-Output ""
            Write-Output "Error installing .NET Desktop Runtime: $_"
            return $false
        }
    }
}

function Install-DCU {
    Write-Output "Installing Dell Command Update..."
    try {
        winget install Dell.CommandUpdate -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -ne 0) { throw "winget exited $LASTEXITCODE" }
        return $true
    } catch {
        try {
            # NOTE: Update this URL when a new DCU version ships
            $uri  = "https://dl.dell.com/FOLDER13309588M/1/Dell-Command-Update-Windows-Universal-Application_C8JXV_WIN64_5.5.0_A00.EXE"
            $path = "$PSScriptRoot\Dell-Command-Update_5.5.0.exe"
            Invoke-WebRequest -Uri $uri -OutFile $path -UseBasicParsing -ErrorAction Stop
            Test-DownloadedInstallerSignature -Path $path -ExpectedSignerPattern 'O=Dell'
            # /s = silent, /l = log path
            $proc = Start-Process -Wait -FilePath $path -ArgumentList '/s',"/l=$PSScriptRoot\dcu-install.log" -PassThru
            if ($proc.ExitCode -notin @(0, 3010)) { throw "Installer exited $($proc.ExitCode)" }
            if ($proc.ExitCode -eq 3010) { $script:AnyRebootNeeded = $true }
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
            return $true
        } catch {
            Write-Output ""
            Write-Output "Error installing Dell Command Update: $_"
            return $false
        }
    }
}

########################

$results = [ordered]@{}
try { $results['Edge']   = Install-Edge   } catch { Write-Error "Error installing Edge: $_";   $results['Edge']   = $false }
try { $results['Chrome'] = Install-Chrome } catch { Write-Error "Error installing Chrome: $_"; $results['Chrome'] = $false }
try { $results['.NET']   = Install-DotNet } catch { Write-Error "Error installing .NET Desktop Runtime: $_"; $results['.NET'] = $false }

# WIP: DCU installer via direct download still returns Access Denied on some images.
# Winget path works when available; direct download is the fallback.
try { $results['DCU']    = Install-DCU    } catch { Write-Error "Error installing Dell Command Update: $_"; $results['DCU'] = $false }

$failedComponents = $results.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key }
if ($failedComponents) {
    Write-Output ""
    Write-Output "One or more components failed to install: $($failedComponents -join ', ')"
    exit 1
}
if ($script:AnyRebootNeeded) {
    Write-Output ""
    Write-Output "One or more components installed successfully but require a reboot."
    exit 3010
}
exit 0
