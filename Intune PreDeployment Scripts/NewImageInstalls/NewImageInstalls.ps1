#Requires -RunAsAdministrator
param (
    [string]$Architecture = "x64",
    [string]$Platform     = "Windows",
    [string]$Channel      = "Stable"
)

$ProgressPreference = 'SilentlyContinue'   # speeds up Invoke-WebRequest downloads

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

function Install-Chrome {
    Write-Output ""
    Write-Output "Installing Google Chrome..."
    try {
        $uri  = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
        $path = "$PSScriptRoot\googlechromestandaloneenterprise64.msi"
        Invoke-WebRequest -Uri $uri -OutFile $path -UseBasicParsing -ErrorAction Stop
        Test-DownloadedInstallerSignature -Path $path -ExpectedSignerPattern 'O=Google LLC'
        $proc = Start-Process msiexec.exe -ArgumentList "/i `"$path`" /qn /norestart" -Wait -PassThru
        if ($proc.ExitCode -notin @(0, 3010, 1641)) {
            throw "msiexec exited $($proc.ExitCode)"
        }
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Output ""
        Write-Output "Error installing Chrome: $_"
        return $false
    }
}

function Install-Edge {
    Write-Output ""
    Write-Output "Installing Microsoft Edge..."

    $apiUrl = "https://edgeupdates.microsoft.com/api/products?view=enterprise"

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Error "Failed to retrieve Edge API JSON: $_"
        return $false
    }

    $channelObj = $response | Where-Object { $_.Product -eq $Channel }
    if (-not $channelObj) { Write-Error "Channel '$Channel' not found in API response."; return $false }

    $filtered = $channelObj.Releases |
        Where-Object { $_.Platform -eq $Platform -and $_.Architecture -eq $Architecture }
    if (-not $filtered) { Write-Error "No releases found for $Platform/$Architecture."; return $false }

    $latestRelease = $filtered | Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
    if (-not $latestRelease) { Write-Error "Could not identify the latest Edge release."; return $false }

    $artifact = $latestRelease.Artifacts | Where-Object { $_.Location -match "\.msi$" } | Select-Object -First 1
    if (-not $artifact) { Write-Error "MSI artifact not found for latest Edge release."; return $false }

    try {
        $path = "$PSScriptRoot\MicrosoftEdgeEnterpriseX64.msi"
        Invoke-WebRequest -Uri $artifact.Location -OutFile $path -UseBasicParsing -ErrorAction Stop
        Test-DownloadedInstallerSignature -Path $path -ExpectedSignerPattern 'O=Microsoft Corporation'
        $proc = Start-Process msiexec.exe -ArgumentList "/i `"$path`" /qn /norestart" -Wait -PassThru
        if ($proc.ExitCode -notin @(0, 3010, 1641)) {
            throw "msiexec exited $($proc.ExitCode)"
        }
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Write-Output "Error installing Edge: $_"
        return $false
    }
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
exit 0
