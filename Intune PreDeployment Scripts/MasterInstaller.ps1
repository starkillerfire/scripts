<#
.SYNOPSIS
    Enterprise-grade installer / updater for Adobe Acrobat Pro, Google Chrome, Microsoft Edge,
    Dell Command Update, and Windows Updates.

.DESCRIPTION
    • Uses Winget with exponential back-off retries (silent, license-accepted).
    • Falls back to local PowerShell installers if Winget is unavailable or fails.
    • Skips products already at required version.
    • Logs to file and Windows Event Log.
    • Outputs install summary to JSON.
    • Enforces admin and 64-bit host.
    • Supports proxy detection, offline mode, skip/only filtering.
    • Executes Windows Updates.ps1 if found in subdirectory.
    • Handles MSI exit codes 3010/1641 for reboot.
    • Requires no code-signing.

.NOTES
    Author: Samual Carman - refactor 2025-06-12
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [string[]] $Skip,
    [string[]] $Only,
    [switch]   $Quiet,
    [switch]   $Offline
)

Set-StrictMode -Version Latest

# Sha256 is left blank on purpose for all three entries below. These
# fallback scripts ship alongside this one in the repo - they aren't
# downloaded at runtime - so there's nothing meaningful to pin a hash
# against, and Invoke-FallbackScript's hash check only runs when Sha256 is
# non-empty anyway. If a fallback target is ever changed to pull from an
# external/downloaded source, put a real pinned hash here instead of
# leaving it blank.
# Chrome and Edge both fall back to the same consolidated Browsers\Install-
# Browsers.ps1 now (replacing their old separate Chrome/installChrome.ps1 and
# Edge/Edge.ps1, archived under 'Browser Install Archive') - FallbackArgs
# tells Invoke-FallbackScript which -Browser to pass so it installs just the
# one product instead of showing its interactive menu.
$Products = @(
    @{ Name = 'Acrobat'; WingetId = 'Adobe.Acrobat.Pro';
       Fallback = Join-Path $PSScriptRoot 'Acrobat/installAcrobat.ps1'; FallbackArgs = @();
       # 'Adobe Acrobat DC*' (not a bare '*') is intentional: Acrobat/Standard
       # DC's real uninstall-registry DisplayName is "Adobe Acrobat DC"
       # (optionally with a trailing qualifier), while Reader DC's is
       # "Adobe Acrobat Reader DC" - the literal "DC" immediately after
       # "Adobe Acrobat " only appears on the non-Reader product, so this
       # anchored pattern matches Pro/DC without also matching Reader if it
       # were ever present. Get-InstalledVersion only does a plain -like,
       # with no separate exclusion mechanism, so the pattern itself has to
       # carry that distinction.
       Sha256   = ''; DisplayNamePattern = 'Adobe Acrobat DC*' },
    @{ Name = 'Chrome' ; WingetId = 'Google.Chrome';
       Fallback = Join-Path $PSScriptRoot 'Browsers/Install-Browsers.ps1'; FallbackArgs = @('-Browser', 'Chrome');
       Sha256   = ''; DisplayNamePattern = 'Google Chrome' },
    @{ Name = 'Edge'   ; WingetId = 'Microsoft.Edge';
       Fallback = Join-Path $PSScriptRoot 'Browsers/Install-Browsers.ps1'; FallbackArgs = @('-Browser', 'Edge');
       # Deliberately an EXACT match, not a wildcard: "Microsoft Edge*" would
       # also match "Microsoft Edge WebView2 Runtime" and "Microsoft Edge
       # Update", both commonly present alongside real Edge, and
       # Get-InstalledVersion's Select-Object -First 1 has no ordering
       # guarantee against the real Edge entry - a wildcard here risks
       # silently reading WebView2's version instead of the browser's.
       Sha256   = ''; DisplayNamePattern = 'Microsoft Edge' }
)

$LogPath     = Join-Path $PSScriptRoot 'master-install.log'
$JsonPath    = Join-Path $PSScriptRoot 'install-summary.json'
$EventSource = 'MasterInstaller'
$MaxLogSize  = 1MB

function Initialize-Logging {
    if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -ge $MaxLogSize) {
        $backup = "$LogPath.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
        Move-Item $LogPath $backup -Force
    }
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        try { New-EventLog -LogName Application -Source $EventSource } catch { Write-Log -Level 'Warning' -Message "Failed to create event log source '$EventSource': $($_.Exception.Message)" }
    }
    Start-Transcript -Path $LogPath -Append | Out-Null
}

function Write-Log {
    param(
        [ValidateSet('Information','Warning','Error')][string] $Level,
        [string] $Message,
        [int]    $EventId = 1000
    )
    $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    if (-not $Quiet) { Write-Host "$stamp [$Level] $Message" }
    try {
        Write-EventLog -LogName Application -Source $EventSource -EventId $EventId -EntryType $Level -Message $Message
    } catch { Write-Host "Failed to write to event log: $($_.Exception.Message)" }
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log -Level 'Error' -Message 'Administrator privileges required.' -EventId 1003
        throw 'Run PowerShell as Administrator.'
    }
}

function Assert-64BitHost {
    # Only x86 is genuinely 32-bit; AMD64 and ARM64 are both legitimate
    # 64-bit host architectures. The previous '-ne AMD64' check would also
    # fire on native ARM64 Windows (where PROCESSOR_ARCHITECTURE is ARM64),
    # relaunching under an "AMD64" powershell.exe path that would itself
    # report ARM64 again - an infinite relaunch loop.
    if ($env:PROCESSOR_ARCHITECTURE -eq 'x86') {
        $ps64 = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        Write-Log -Level 'Information' -Message 'Re-launching under 64-bit PowerShell…' -EventId 1000
        & $ps64 -NoLogo -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
        exit $LASTEXITCODE
    }
}

function Enable-Tls12 { try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch { Write-Log -Level 'Warning' -Message "Failed to enable TLS 1.2: $($_.Exception.Message)" } }

function Set-ProxyFromRegistry {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $ps  = Get-ItemProperty -Path $reg -Name ProxyServer,ProxyEnable -ErrorAction SilentlyContinue
    if ($ps.ProxyEnable -and $ps.ProxyServer) { $env:HTTPS_PROXY = "http://$($ps.ProxyServer)" }
}

function Test-FileHashMatch {
    param([string] $Path, [string] $Sha256)
    if (-not (Test-Path $Path)) { return $false }
    $calc = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    return ($calc -eq $Sha256.ToUpperInvariant())
}

function Invoke-WingetInstall {
    param([Parameter(Mandatory)][string] $Id, [int] $Retries = 3)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }

    for ($i = 1; $i -le $Retries; $i++) {
        Write-Log -Level 'Information' -Message "Winget install attempt $($i): $Id"   # ← fixed
        & $winget install --id $Id --accept-package-agreements --accept-source-agreements --silent --disable-interactivity | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        if ($LASTEXITCODE -in 3010, 1641) {
            $script:AnyRebootNeeded = $true
            return $true
        }
        Start-Sleep -Seconds ([math]::Pow(2, $i))
    }
    return $false
}

function Invoke-FallbackScript {
    param([Parameter(Mandatory)][string] $Path, [string] $Sha256, [string[]] $ArgumentList = @())
    if (-not (Test-Path $Path)) {
        Write-Log -Level 'Error' -Message "Fallback script missing: $Path"
        throw "Script not found: $Path"
    }
    if ($Sha256 -and -not (Test-FileHashMatch -Path $Path -Sha256 $Sha256)) {
        Write-Log -Level 'Error' -Message "SHA-256 mismatch for $Path"
        throw "Hash validation failed for $Path"
    }

    Write-Log -Level 'Information' -Message "Running fallback script: $Path $($ArgumentList -join ' ')"
    $oldPol = Get-ExecutionPolicy -Scope Process
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        # -ErrorAction Stop here never actually caught a nonzero exit code -
        # only a real launch failure (missing exe, etc.) throws a
        # terminating error for an external process. A fallback script that
        # legitimately failed (e.g. installAcrobat.ps1 exiting 1) fell
        # straight through with no signal to the caller, which then always
        # treated it as a success.
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $Path @ArgumentList
        if ($LASTEXITCODE -in 3010, 1641) { $script:AnyRebootNeeded = $true }
        return ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -in 3010, 1641)
    } finally {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPol -Force
    }
}

function Get-InstalledVersion {
    # Chrome, Edge, and Acrobat are installed via MSI/EXE, not through a
    # PackageManagement provider, so Get-Package by itself almost never
    # finds them - the "already installed, skip" logic further down would
    # never trigger and every run would attempt a redundant reinstall.
    # Checking the uninstall registry keys first, and only falling back to
    # Get-Package for providers that do register themselves, makes the
    # detection actually work for these three products.
    param([string] $Name, [string] $DisplayNamePattern)
    if ($DisplayNamePattern) {
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $entry = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like $DisplayNamePattern } |
            Select-Object -First 1
        if ($entry -and $entry.DisplayVersion) { return $entry.DisplayVersion }
    }
    try {
        $pkg = Get-Package -Name $Name -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
        return $pkg.Version
    } catch { return $null }
}

function Install-DellCommandUpdate {
    # The DCU folder ships only the real installer script ("Dell command
    # update install and update.ps1") - no dcu-cli.exe or *.msi lives in
    # this folder directly, so the previous binary-lookup logic here never
    # found anything to run. Invoke that script the same way the Windows
    # Updates script is invoked below (execution-policy save/restore around
    # a child powershell.exe -File call, then check $LASTEXITCODE - a
    # nonzero external-process exit code doesn't throw a terminating error,
    # so this can't rely on try/catch to detect failure).
    #
    # IMPORTANT: the DCU script's own exit code (see its final `exit
    # ([int]$exitCode)`) is dcu-cli.exe's raw /applyUpdates exit code, Dell's
    # own scheme - NOT an MSI/Intune code. Per Dell's dcu-cli reference, 0 =
    # success/no reboot and 1 = success/reboot required; 3010/1641 mean
    # nothing in this context and previously caused a real "reboot required"
    # result (code 1) to be misread as a failure. The DCU script's own catch
    # block separately uses exit 500 as its "internal script error, retry
    # scheduled via RunOnce" sentinel - also not a dcu-cli code, so it's
    # handled as its own case here rather than falling into the generic
    # failure branch.
    #
    # -NoReboot is passed below so dcu-cli itself never triggers a reboot mid-
    # run (it would otherwise kill this MasterInstaller process the same way
    # Windows Updates.ps1's own forced reboot used to, before that was fixed
    # with -NoImmediateReboot) - "reboot required" is instead reported purely
    # via exit code 1 above, same as every other step in this script.
    param([Parameter(Mandatory)][string] $FolderPath)
    Write-Log -Level 'Information' -Message '=== Processing Dell Command Update ==='
    $dcuScript = Join-Path $FolderPath 'Dell command update install and update.ps1'
    if (-not (Test-Path $dcuScript)) {
        Write-Log -Level 'Error' -Message "DCU install script not found: $dcuScript"
        return @{ Status = 'Missing' }
    }

    $oldPol = Get-ExecutionPolicy -Scope Process
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $dcuScript -NoReboot
        switch ($LASTEXITCODE) {
            0 {
                Write-Log -Level 'Information' -Message 'DCU script completed successfully.'
                return @{ Status = 'Installed/Updated'; Version = 'via-Script' }
            }
            1 {
                Write-Log -Level 'Information' -Message 'DCU script completed successfully (reboot required).'
                $script:AnyRebootNeeded = $true
                return @{ Status = 'Installed/Updated'; Version = 'via-Script' }
            }
            500 {
                Write-Log -Level 'Error' -Message 'DCU script failed internally; it has scheduled its own RunOnce retry for next boot.'
                return @{ Status = 'Failed_WillRetryNextBoot' }
            }
            default {
                Write-Log -Level 'Error' -Message "DCU script (dcu-cli) exited with code $LASTEXITCODE."
                return @{ Status = "Failed_ExitCode_$LASTEXITCODE" }
            }
        }
    } finally {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPol -Force
    }
}

#===================  MAIN  ===================#

try {
    Initialize-Logging
    Write-Log -Level 'Information' -Message '=== MasterInstaller started ==='
    Assert-Admin
    Assert-64BitHost
    Enable-Tls12
    Set-ProxyFromRegistry

    $summary     = @{}
    $needsReboot = $false
    $script:AnyRebootNeeded = $false
    $total       = $Products.Count
    $index       = 0

    foreach ($product in $Products) {
        $index++
        if ($Skip -and ($product.Name -in $Skip))     { continue }
        if ($Only -and ($product.Name -notin $Only)) { continue }

        Write-Progress -Activity 'MasterInstaller' -Status "Processing $($product.Name)" -PercentComplete ([int](($index / $total) * 100))
        Write-Log -Level 'Information' -Message "=== Processing $($product.Name) ==="

        $installed = Get-InstalledVersion -Name $product.Name -DisplayNamePattern $product.DisplayNamePattern
        if ($installed) {
            Write-Log -Level 'Information' -Message "$($product.Name) already installed - version $installed"
            $summary[$product.Name] = @{ Status = 'AlreadyInstalled'; Version = "$installed" }
            continue
        }

        $success = $false
        if (-not $Offline) {
            $success = Invoke-WingetInstall -Id $product.WingetId
        }
        if (-not $success) {
            Write-Log -Level 'Warning' -Message "Winget unavailable or failed for $($product.Name); falling back"
            $success = Invoke-FallbackScript -Path $product.Fallback -Sha256 $product.Sha256 -ArgumentList $product.FallbackArgs
        }

        if ($success) {
            $ver = Get-InstalledVersion -Name $product.Name -DisplayNamePattern $product.DisplayNamePattern
            Write-Log -Level 'Information' -Message "$($product.Name) installed - version $ver"
            $summary[$product.Name] = @{ Status = 'Installed'; Version = "$ver" }
        } else {
            Write-Log -Level 'Error' -Message "$($product.Name) failed to install"
            $summary[$product.Name] = @{ Status = 'Failed' }
        }
    }

    #----------- Dell Command Update -----------#
    $dcuFolder = Join-Path $PSScriptRoot 'DCU'
    if (Test-Path $dcuFolder) {
        $summary['DellCommandUpdate'] = Install-DellCommandUpdate -FolderPath $dcuFolder
    } else {
        Write-Log -Level 'Information' -Message 'DCU folder not found - skipping Dell Command Update.'
        $summary['DellCommandUpdate'] = @{ Status = 'Skipped' }
    }

    #----------- Windows Updates script --------#
    $wuScriptPath = Join-Path $PSScriptRoot 'Windows Updates\Windows Updates.ps1'
    if (Test-Path $wuScriptPath) {
        Write-Log -Level 'Information' -Message '=== Processing Windows Updates script ==='
        try {
            $oldPol = Get-ExecutionPolicy -Scope Process
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
            & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $wuScriptPath -NoImmediateReboot
            # A nonzero exit code from an external process does not throw a
            # terminating PowerShell error (even with -ErrorAction Stop), so
            # this always logged "completed successfully" regardless of
            # whether Windows Updates.ps1 actually failed.
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Level 'Information' -Message 'Windows Updates script completed successfully.'
                $summary['WindowsUpdates'] = @{ Status = 'Completed'; Script = 'Windows Updates.ps1' }
            } else {
                Write-Log -Level 'Warning' -Message "Windows Updates script exited with code $LASTEXITCODE."
                $summary['WindowsUpdates'] = @{ Status = "ExitCode_$LASTEXITCODE"; Script = 'Windows Updates.ps1' }
                if ($LASTEXITCODE -in 3010, 1641) { $script:AnyRebootNeeded = $true }
            }
        } catch {
            Write-Log -Level 'Error' -Message "Windows Updates script failed: $_"
            $summary['WindowsUpdates'] = @{ Status = 'Failed'; Error = "$_" }
        } finally {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPol -Force
        }
    } else {
        Write-Log -Level 'Information' -Message 'Windows Updates script not found - skipping.'
        $summary['WindowsUpdates'] = @{ Status = 'Skipped' }
    }

    #----------- Finalise -----------#
    # Derived from each install path's actual recorded exit code
    # ($script:AnyRebootNeeded, set in Invoke-WingetInstall/
    # Invoke-FallbackScript/Install-DellCommandUpdate) instead of a raw
    # substring search over the whole transcript - that used to match on
    # "3010"/"1641" appearing anywhere at all (a URL, a version string, a
    # timestamp), with no structural link to which product actually needed
    # a reboot.
    if ($script:AnyRebootNeeded) { $needsReboot = $true }
    $summary['NeedsReboot'] = $needsReboot
    $summary['Completed']   = (Get-Date).ToString('o')

    $summary | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding UTF8

    if ($needsReboot) {
        Write-Log -Level 'Warning' -Message 'One or more installers requested a reboot.'
        if (-not $Quiet) { Write-Warning 'System reboot required to complete installation.' }
    }

    Write-Log -Level 'Information' -Message '=== MasterInstaller completed successfully ==='
    if ($needsReboot) {
        # 3010 is the standard MSI/Intune "success, reboot required" signal -
        # exiting 0 here would let Intune mark the deployment complete while
        # masking the fact that a child installer is still waiting on a
        # restart to finish.
        Exit 3010
    }
    Exit 0
} catch {
    Write-Log -Level 'Error' -Message "Unhandled exception: $_"
    Exit 1
} finally {
    Stop-Transcript | Out-Null
    Write-Progress -Activity 'MasterInstaller' -Completed -Status 'Done'
}
