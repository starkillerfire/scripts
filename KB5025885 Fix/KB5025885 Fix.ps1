#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Mitigates CVE-2023-24932 (BlackLotus) on Windows 10 21H2/22H2 via the four Secure-Boot servicing phases.

.DESCRIPTION
    SecureBoot-Mitigation_Win10.ps1 - v2025-06-18 - PowerShell 5.1

    Gates on a dynamic build check, Secure Boot / pending-reboot state, and a BitLocker-suspended
    precondition, then runs the four Secure-Boot phases via the built-in
    \Microsoft\Windows\PI\Secure-Boot-Update scheduled task. The pre-patch boot manager is backed
    up to $env:SystemDrive\EFI_Backup before Phase 2 replaces it, and old backups are pruned.
    BitLocker protectors on C: are re-enabled once phase execution finishes, on every exit path
    (success, partial failure, or an unhandled error caught by the script's trap) - not only the
    all-phases-succeeded path.

    -UpdateWinRE locates the WinRE directory and warns that its SafeOS Dynamic Update must still
    be applied manually; this script does not apply it. -ExportRecoveryUSB optionally exports the
    current WinRE image to a USB drive first.

    (c) Samual Carman CPN-CCAO - Version 1.3

.PARAMETER Silent
    Suppress console (Write-Host) output. Logging to the event log and transcript still occurs.

.PARAMETER WhatIf
    Preview mode - reports what each phase would do without making any registry, scheduled-task,
    or BitLocker changes.

.PARAMETER AutoReboot
    Automatically restart the computer after a successful mitigation, after waiting -RebootDelay
    seconds.

.PARAMETER RebootDelay
    Seconds to wait before rebooting when -AutoReboot is specified. Default: 60.

.PARAMETER PauseBetweenPhases
    Pause for operator confirmation (Enter) after each phase completes. If BitLocker is still off
    at that point, a warning is printed immediately before the prompt.

.PARAMETER PhaseTimeoutSeconds
    Seconds to wait for a phase's expected completion event(s) before marking it failed. Default: 120.

.PARAMETER UpdateWinRE
    Locate the WinRE directory and warn that its SafeOS Dynamic Update must be applied manually -
    this switch does not apply the update itself.

.PARAMETER ExportRecoveryUSB
    Drive letter of a removable USB drive to export the current WinRE image to. If omitted while
    this step is requested, the first removable drive >= 8 GB is used.

.PARAMETER CheckForNewerBuildOnline
    Additionally check support.microsoft.com for a fixed build number newer than the pinned
    baseline, and use it if found. The online check can only raise the build gate, never lower it.

.PARAMETER LogPath
    Path to the transcript/log file. Default: $env:SystemDrive\Logs\CVE-2023-24932-Mitigation.log
#>

[CmdletBinding()] param(
    [switch]$Silent,
    [switch]$WhatIf,
    [switch]$AutoReboot,
    [int]   $RebootDelay       = 60,
    [switch]$PauseBetweenPhases,
    [int]   $PhaseTimeoutSeconds = 120,
    [switch]$UpdateWinRE,
    [string]$ExportRecoveryUSB,
    [switch]$CheckForNewerBuildOnline,
    [string]$LogPath = [IO.Path]::Combine($env:SystemDrive,'Logs','CVE-2023-24932-Mitigation.log')
)

# ── Logging ───────────────────────────────────────────────────────────────
trap {
    # Without this, any unhandled error anywhere in the script exits silently
    # via the bare "exit 1" below - the transcript captures nothing about
    # what actually went wrong, only that the script stopped. Log the real
    # exception (falling back to a direct file write if Write-Log itself
    # isn't available/fails, e.g. an error before it's defined) before
    # stopping the transcript, so the failure is actually traceable.
    $trapMsg = "FATAL: Unhandled error: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    try { Write-Log $trapMsg 'Error' } catch { try { Add-Content -Path $LogPath -Value "$(Get-Date -Format 'u') $trapMsg" -ErrorAction SilentlyContinue } catch {} }
    try { Stop-Transcript } catch { }
    exit 1
}

function Write-Log {
    param([string]$Msg,[ValidateSet('Information','Warning','Error')]$Level='Information')
    if (-not $Silent) { Write-Host $Msg }
    if (-not (Get-EventLog -LogName Application -Source SecureBootMitigation -ErrorAction SilentlyContinue)) {
        New-EventLog -LogName Application -Source SecureBootMitigation -ErrorAction SilentlyContinue
    }
    Write-EventLog -LogName Application -Source SecureBootMitigation -EntryType $Level -EventId 5500 -Message $Msg
}

# ── Admin check & transcript ──────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}
Start-Transcript -Path $LogPath -Append
$ScriptStart = Get-Date

# Don't rely on the OS/.NET default protocol for the support.microsoft.com
# scrape below - freshly-imaged machines may not yet default to TLS 1.2.
if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

# ── Build gate ────────────────────────────────────────────────────────────
# Pinned to the known-good fixed build for CVE-2023-24932 on Windows 10
# 21H2/22H2 as of this script's last update. This used to scrape Microsoft's
# support page for "the current fixed build" on every run, which is fragile
# - a page redesign or wording change silently breaks the regex, and a bad
# match could under- or over-gate this mitigation with no obvious symptom.
# The pinned value below is authoritative by default. Pass
# -CheckForNewerBuildOnline to additionally check that page for a build
# number newer than the pinned one (e.g. if a later cumulative update also
# addressed this and you want the gate raised accordingly) - the online
# check can only raise the gate, never lower it below the pinned baseline.
$PinnedMinBuild = [version]'19045.4651'

function Get-FixedBuild {
    if (-not $CheckForNewerBuildOnline) { return $PinnedMinBuild }
    $uri = 'https://support.microsoft.com/en-us/topic/41a975df-beb2-40c1-99a3-b3ff139f832d'
    try {
        $html = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 15
        if ($html.Content -match '(19\d{3}\.\d{3,4})') {
            $scraped = [version]$Matches[1]
            if ($scraped -gt $PinnedMinBuild) {
                Write-Log "Found a newer fixed build ($scraped) than the pinned baseline ($PinnedMinBuild) - using it." 'Information'
                return $scraped
            }
        }
    } catch { Write-Log "Build scrape failed; using pinned baseline $PinnedMinBuild" 'Warning' }
    return $PinnedMinBuild
}
$MinBuild  = Get-FixedBuild
# CurrentBuildNumber alone (e.g. "19045") has no dot and isn't a valid
# [version] on its own - casting it directly throws every time, which the
# top-level trap swallows into a silent "exit 1" before any mitigation
# logic runs. UBR (Update Build Revision) supplies the part after the dot,
# matching the "19045.4651" shape $PinnedMinBuild is already in.
$cvKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$CurBuild = [version]"$($cvKey.CurrentBuildNumber).$($cvKey.UBR)"
if ($CurBuild -lt $MinBuild) { throw "OS build $CurBuild < $MinBuild - install latest CU." }

# ── Environment guards ────────────────────────────────────────────────────
if (-not (Confirm-SecureBootUEFI)) { throw 'Secure Boot disabled or legacy BIOS.' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    throw 'A reboot is pending - restart and rerun.'
}
if ((Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus -eq 'On') {
    throw 'Suspend BitLocker protection on C: first.'
}

# ── Helper functions ─────────────────────────────────────────────────────-
function Get-FreeDrive       { (65..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Get-PSDrive $_ -ea 0) } | Select-Object -First 1) + ':' }
function Mount-Efi           { $d = Get-FreeDrive; mountvol $d /s > $null; return $d }
function Dismount-Efi([string]$d) { mountvol $d /d > $null }

function Test-CA2023  { ([Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db ).Bytes))  -match 'Windows UEFI CA 2023' }
function Test-DBXGood { ([Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name dbx).Bytes)) -notmatch 'Windows Production PCA 2011' }

# ── Optional WinRE SafeOS DU ──────────────────────────────────────────────
function Update-WinRE {
    # This only locates and reports the WinRE directory - it does NOT
    # download or apply a SafeOS Dynamic Update. Doing that safely requires
    # mounting the WinRE image via DISM and applying the specific SafeOS DU
    # package for this exact build, whose download URL/KB varies by build
    # and isn't something to guess at here. Applying it is a manual step;
    # this function's job is only to point the operator at where to do it.
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    $info = reagentc /info 2>&1
    if ($LASTEXITCODE -ne 0 -or $info -match 'Disabled') { Write-Log 'WinRE disabled; SafeOS DU skipped.' 'Warning'; return }
    $loc  = ($info | Select-String 'WinRE location').Line
    if (-not $loc) { Write-Log 'Cannot locate WinRE.' 'Warning'; return }
    $winreDir = $loc.Split(':',2)[1].Trim()
    if ($PSCmdlet.ShouldProcess($winreDir, 'Report WinRE location and required manual SafeOS Dynamic Update')) {
        Write-Log ("WinRE directory found: {0}" -f $winreDir)
        Write-Log '-UpdateWinRE does not apply the SafeOS Dynamic Update automatically. WinRE boot components remain unpatched against this CVE until the matching SafeOS DU for this exact build is applied manually (mount the WinRE image with DISM /Mount-Image and apply the SafeOS DU package for this OS build, then DISM /Unmount-Image /Commit).' 'Warning'
    }
}

# ── Optional USB export of WinRE ───────────────────────────────────────────
function Export-WinRE {
    param([string]$Letter)
    if (-not $Letter) {
        $Letter = (Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.Size -ge 8GB } |
                   Select-Object -Expand DriveLetter -First 1)
        if (-not $Letter) { throw 'No USB ≥ 8 GB found.' }
    }
    $dst = ('{0}:\Recovery\WindowsRE' -f $Letter)
    if (-not (Test-Path $dst)) { New-Item -Path $dst -ItemType Directory -Force > $null }
    $srcDir = (reagentc /info | Select-String 'WinRE location').Line.Split(':',2)[1].Trim()
    Copy-Item (Join-Path $srcDir 'Winre.wim') (Join-Path $dst 'Winre.wim') -Force
    Copy-Item 'C:\Windows\System32\Recovery\ReAgent.xml' (Join-Path $dst 'ReAgent.xml') -Force -ea 0
    Write-Log "WinRE exported to $dst"
}

# ── Secure-Boot phase executor ────────────────────────────────────────────
function Invoke-Phase {
    param([string]$Name,[int]$Mask,[int[]]$Events,[ref]$Result)
    Write-Log "→ $Name"
    if ($WhatIf) {
        Write-Log "[WhatIf] Would set AvailableUpdates=0x$([Convert]::ToString($Mask,16))"
        # Report this phase as "would succeed" instead of leaving $Result at
        # its $false default - otherwise every -WhatIf run falls through the
        # "$P1 -and $P2 -and $P3 -and $P4" gate below as if it had actually
        # failed, logging an Error-level "Mitigation failed" event and
        # exiting 1 for what was only ever a preview.
        $Result.Value = $true
        return
    }
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Force > $null
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -Value $Mask -Type DWord -Force
    Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update'
    # A flat Start-Sleep before checking for the completion events raced the
    # task on slower/loaded hardware - the task hadn't finished yet, so the
    # events genuinely weren't there, and the phase was marked failed for a
    # reason that would have resolved moments later. Poll for up to
    # $PhaseTimeoutSeconds instead of sleeping a fixed amount once.
    $deadline = (Get-Date).AddSeconds($PhaseTimeoutSeconds)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        $ok = $true
        foreach ($e in $Events) {
            if (-not (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Boot/Operational';Id=$e;StartTime=$ScriptStart} -MaxEvents 1 -ErrorAction SilentlyContinue)) {
                $ok = $false
            }
        }
        if ($ok) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $ok) {
        foreach ($e in $Events) {
            if (-not (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Boot/Operational';Id=$e;StartTime=$ScriptStart} -MaxEvents 1 -ErrorAction SilentlyContinue)) {
                Write-Log "Event $e missing after ${PhaseTimeoutSeconds}s." 'Warning'
            }
        }
    }
    $Result.Value = $ok
    if ($PauseBetweenPhases -and -not $Silent -and -not $WhatIf) {
        # Read-Host blocks indefinitely with no timeout - if BitLocker is
        # still off at this point (it is, until phase execution finishes),
        # make that state impossible to miss for anyone who walks up to
        # this prompt, not just whoever started the run.
        if ((Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus -eq 'Off') {
            Write-Log 'WARNING: BitLocker protection is currently OFF on this machine and will not be restored until this script finishes running.' 'Warning'
        }
        Read-Host 'ENTER to continue…'
    }
}

# ── BitLocker re-enable ───────────────────────────────────────────────────
# The precondition check above guarantees BitLocker is off before phase
# execution starts. It used to only be re-enabled in the normal-completion
# branch below the phase calls - any unhandled exception during phase
# execution went straight to the top-level trap and exited without ever
# restoring it. $script:bitlockerReenableAttempted makes this idempotent so
# it's safe to call from both the finally block below (which runs on every
# exit path, including a normal completion) and it still only acts once.
$script:bitlockerReenableAttempted = $false
function Restore-BitLockerProtection {
    if ($script:bitlockerReenableAttempted) { return }
    $script:bitlockerReenableAttempted = $true
    if ($WhatIf) { return }
    try {
        if ((Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus -eq 'Off') {
            manage-bde -protectors -enable C: > $null
            Write-Log 'BitLocker protectors re-enabled.'
        }
    } catch {
        Write-Log "FAILED to re-enable BitLocker protectors: $($_.Exception.Message) - MANUAL ACTION REQUIRED: run 'manage-bde -protectors -enable C:' on this machine." 'Error'
    }
}

# ── Optional steps + Run phases ───────────────────────────────────────────
# Wrapped in try/finally so Restore-BitLockerProtection runs on every exit
# path out of this section - normal completion, or an unhandled exception
# that propagates up to the top-level trap - not only the two spots that
# used to call it explicitly.
try {
    if ($UpdateWinRE)       { Update-WinRE }
    if ($ExportRecoveryUSB) { Export-WinRE -Letter $ExportRecoveryUSB }

    $P1=$P2=$P3=$P4=$false
    if (-not (Test-CA2023)) { Invoke-Phase 'Phase 1 - Add CA 2023'   0x40  @(1036)          ([ref]$P1) } else { $P1=$true }

    # Back up the CURRENT (pre-patch) boot manager BEFORE Phase 2 installs the new
    # one. This used to run after Phase 2 had already returned, which captured
    # the file Phase 2 had already replaced - the "backup" preserved no way to
    # roll back to the original boot manager if the patch caused a boot problem,
    # defeating the entire purpose of $backupDir.
    if (-not $WhatIf) {
        $efi = Mount-Efi
        try {
            $backupDir = [IO.Path]::Combine($env:SystemDrive,'EFI_Backup')
            if (-not (Test-Path $backupDir)) { New-Item $backupDir -ItemType Directory > $null }
            # Restrict the backup directory to admins - it holds a copy of
            # the boot manager binary and shouldn't be world-readable.
            icacls $backupDir /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' > $null
            if ($LASTEXITCODE -ne 0) { Write-Log "Failed to set restrictive ACL on ${backupDir} (icacls exit $LASTEXITCODE)." 'Warning' }

            Copy-Item (Join-Path $efi 'EFI\Microsoft\Boot\bootmgfw.efi') `
                      (Join-Path $backupDir ("bootmgfw_{0:yyyyMMdd_HHmmss}.efi" -f (Get-Date))) -Force

            # Backups accumulate on every run otherwise - prune anything
            # older than 30 days, matching the retention window this repo
            # already uses elsewhere (e.g. Invoke-FleetPatchSweep's $LogRetentionDays).
            Get-ChildItem $backupDir -Filter 'bootmgfw_*.efi' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } finally {
            Dismount-Efi $efi
        }
    }

    Invoke-Phase             'Phase 2 - New bootmgr'    0x100 @(1799)          ([ref]$P2)
    if (-not (Test-DBXGood)) { Invoke-Phase 'Phase 3 - Revoke PCA 2011' 0x180 @(1037,1801)     ([ref]$P3) } else { $P3=$true }
    Invoke-Phase             'Phase 4 - SVN lock-in'    0x280 @(1800,1796,1797,1798) ([ref]$P4)
} finally {
    Restore-BitLockerProtection
}

# ── Summary ───────────────────────────────────────────────────────────────
# $WhatIf is checked first and short-circuits before any real change here
# (Remove-ItemProperty) - without this, a WhatIf run where every phase
# reported "would succeed" would fall into the real-mitigation branch and
# actually clear the registry value for real. BitLocker re-enable already
# happened above regardless of $WhatIf/$ok - see Restore-BitLockerProtection.
if ($WhatIf) {
    Write-Log 'WhatIf preview complete - no changes were made.'; $exit = 0
} else {
    if ($P1 -and $P2 -and $P3 -and $P4) {
        Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -ea 0
        Write-Log 'Mitigation complete.'; $exit = 0
    } else {
        Write-Log 'Mitigation failed - one or more phases did not complete. BitLocker protection has been restored regardless; rerun this script to retry the mitigation.' 'Error'
        $exit = 1
    }
}

Stop-Transcript
if ($AutoReboot -and $exit -eq 0) { Start-Sleep $RebootDelay; Restart-Computer -Force }
exit $exit
