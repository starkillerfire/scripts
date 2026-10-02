#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LogDir = 'C:\ProgramData\UpdateAll\Logs',
    [int]$MinFreeGB = 8,
    [string[]]$SkipKB = @(),
    [string[]]$ForceKB = @(),
    [string]$PatchWindow = '',
    [string]$ConfigPath = 'C:\ProgramData\UpdateAll\config.json',
    [string]$SelfUpdateSource = '',
    [string]$ExpectedSha256 = '',
    [ValidateScript({$_ -match '^https://'})]
    [string]$LogEndpoint = '',
    [switch]$WingetCatchUp,
    [switch]$IgnoreBattery,
    [switch]$EnableVerbose,
    # When set, a pending reboot registers the resume task (so the update
    # loop still continues after whatever reboot eventually happens) and
    # exits 3010 instead of calling Restart-Computer -Force. Needed when this
    # script is launched as a waited child process (e.g. by
    # MasterInstaller.ps1) - an immediate forced reboot previously killed the
    # parent mid-run, before it could finalize its own summary/transcript.
    [switch]$NoImmediateReboot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Set before the self-update download below (previously this only happened
# later, after that download had already run unprotected).
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$VerbosePreference = if ($EnableVerbose.IsPresent) { 'Continue' } else { 'SilentlyContinue' }
$script:HadErrors = $false
$script:Skipped = $false

# Only these - the script's own parameters - may be set from config.json.
# Set-Variable -Force below can create or overwrite ANY variable in this
# scope by name, so without this allow-list a config file could just as
# easily clobber an internal variable (e.g. $script:HadErrors, $freeGB) as
# fill in a real parameter.
$AllowedConfigKeys = @(
    'LogDir', 'MinFreeGB', 'SkipKB', 'ForceKB', 'PatchWindow', 'ConfigPath',
    'SelfUpdateSource', 'ExpectedSha256', 'LogEndpoint', 'WingetCatchUp',
    'IgnoreBattery', 'EnableVerbose', 'NoImmediateReboot'
)

if (Test-Path $ConfigPath) {
    try {
        $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        # Fill in values from the config file only for parameters the
        # caller did NOT explicitly pass - the previous condition checked
        # $PSBoundParameters.Keys (only params already passed on the
        # command line) instead of the inverse, so on a normal no-argument
        # run (the common case, where $PSBoundParameters is empty) the
        # config file was silently ignored entirely, and on any run where
        # it did fire, it backwards-clobbered explicit CLI values with the
        # config defaults instead of filling in what was missing.
        foreach ($prop in $cfg.PSObject.Properties) {
            if ($prop.Name -notin $AllowedConfigKeys) {
                Write-Warning "Ignoring unrecognized config key '$($prop.Name)' in ${ConfigPath}"
                continue
            }
            if (-not $PSBoundParameters.ContainsKey($prop.Name)) { Set-Variable -Name $prop.Name -Value $prop.Value -Force }
        }
    } catch { Write-Warning "Failed to load config file ${ConfigPath}: $($_.Exception.Message)" }
}

function Write-UpdateEvent {
    param([string]$m, [System.Diagnostics.EventLogEntryType]$t, [int]$id)
    if (-not [Diagnostics.EventLog]::SourceExists('Update-All')) { New-EventLog Application 'Update-All' }
    # Named parameters here on purpose: Write-EventLog's positional order
    # is LogName, Source, EventId, EntryType, Message - passing $t (an
    # EventLogEntryType) and $id (an int) positionally put them in the
    # EventId/EntryType slots respectively (swapped relative to their real
    # types), which threw a type-conversion error the first time this ran,
    # before any update logic executed.
    Write-EventLog -LogName Application -Source 'Update-All' -EventId $id -EntryType $t -Message $m
}

function Stop-UpdateScript {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param([string]$m, [int]$code)
    if ($code -ne 0) { $script:HadErrors = $true }
    Write-Warning $m
    # 3010 (added by the -NoImmediateReboot path) is a success state - a
    # reboot is needed, not an error - so it's grouped with 0 here instead of
    # falling into the generic Error branch, which would otherwise log a
    # routine, expected outcome as an Application-log error.
    $type = if ($code -in 0, 3010) { [System.Diagnostics.EventLogEntryType]::Information } elseif ($code -eq 1) { [System.Diagnostics.EventLogEntryType]::Warning } else { [System.Diagnostics.EventLogEntryType]::Error }
    Write-UpdateEvent $m $type 6000
    if ($PSCmdlet.ShouldProcess('transcript and Update-All mutex', 'Stop transcript and release mutex')) {
        try { Stop-Transcript } catch { Write-Warning "Stop-Transcript failed: $($_.Exception.Message)" }
        # The mutex is created with initiallyOwned:$false and this thread never
        # calls WaitOne() to take ownership - it's only used as a system-wide
        # "has an instance already started" check via $lockOK (createdNew).
        # ReleaseMutex() requires the calling thread to actually own the mutex,
        # so calling it here always threw. Dispose() just closes this process's
        # handle to the named mutex and needs no ownership.
        try { $script:Mutex.Dispose() } catch { Write-Warning "Mutex dispose failed: $($_.Exception.Message)" }
    }
    exit $code
}

$script:Mutex = [Threading.Mutex]::new($false, 'Global\UpdateAll23H2', [ref]$lockOK)
if (-not $lockOK) { exit 0 }

function Test-IsAdministrator {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

if ($SelfUpdateSource) {
    # ExpectedSha256 here is checked against THIS running script, not the
    # download - it's there to make sure the copy currently executing
    # hasn't been tampered with before it's trusted to fetch its own
    # replacement. Refusing to proceed without it means a compromised or
    # MITM'd SelfUpdateSource can't get unverified code to run just because
    # nobody bothered to set the parameter. The replacement script itself
    # can't be hash-pinned the same way since its hash legitimately changes
    # with every release, so that one is checked via Authenticode below
    # instead.
    if (-not $ExpectedSha256) { Stop-UpdateScript 'SelfUpdateSource set without ExpectedSha256 - refusing to self-update unverified code' 2 }
    try {
        $curHash = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash
        if ($ExpectedSha256 -ne $curHash) { Stop-UpdateScript 'SHA256 mismatch' 2 }
        $tmp = "$env:TEMP\UpdateAll_latest.ps1"
        if ($SelfUpdateSource -match '^https?://') { Invoke-WebRequest $SelfUpdateSource -OutFile $tmp -UseBasicParsing -TimeoutSec 30 }
        else { Copy-Item $SelfUpdateSource $tmp -Force }
        $newHash = (Get-FileHash $tmp -Algorithm SHA256).Hash
        if ($newHash -ne $curHash) {
            $sig = Get-AuthenticodeSignature $tmp
            # Being validly signed isn't enough on its own - that only proves
            # SOME publisher signed it, not that it's ours. Pin the subject too,
            # or any validly-signed script (not just a legitimate update from
            # this org) would pass. Placeholder pattern - no internal
            # code-signing cert is established elsewhere in this repo yet;
            # update this to match whatever this script is actually signed
            # with once that's in place.
            $selfUpdateSignerPattern = 'O=Bureau of Reclamation'
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($selfUpdateSignerPattern)) {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                Stop-UpdateScript "Self-update package failed Authenticode validation (status: $($sig.Status); signer: $($sig.SignerCertificate.Subject)) - refusing to run it" 2
            }
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`""
            exit
        } else { Remove-Item $tmp -Force }
    } catch { Write-Warning "Self-update check failed: $($_.Exception.Message)" }
}

$freeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
if ($freeGB -lt $MinFreeGB) { Stop-UpdateScript "Low disk" 2 }

if (-not $IgnoreBattery) {
    $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($bat -and $bat.BatteryStatus -ne 2) { Stop-UpdateScript 'On battery' 2 }
}

function Test-UpdateWindow {
    param([string]$Spec)
    if (-not $Spec) { return $true }
    $now = Get-Date
    $day = $now.ToString('ddd', [CultureInfo]::InvariantCulture)
    foreach ($s in $Spec -split ';') {
        if ($s -match '^\s*(?<d>[A-Za-z,-]+)\s+(?<a>\d\d:\d\d)-(?<b>\d\d:\d\d)\s*$') {
            if (($matches.d -split ',') -contains $day) {
                $A = [DateTime]::ParseExact($matches.a, 'HH:mm', $null)
                $B = [DateTime]::ParseExact($matches.b, 'HH:mm', $null)
                $start = $now.Date.AddHours($A.Hour).AddMinutes($A.Minute)
                $end = $now.Date.AddHours($B.Hour).AddMinutes($B.Minute)
                if ($end -le $start) { $end = $end.AddDays(1) }
                if ($now -ge $start -and $now -lt $end) { return $true }
            }
        }
    }
    return $false
}
# Wait for the patch window with a 12-hour hard cap to prevent infinite blocking
$patchWindowDeadline = (Get-Date).AddHours(12)
while (-not (Test-UpdateWindow $PatchWindow)) {
    if ((Get-Date) -gt $patchWindowDeadline) { Stop-UpdateScript 'Patch window wait exceeded 12 hours' 2 }
    Start-Sleep 900
}

New-Item $LogDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $LogDir "UpdateAll-$env:COMPUTERNAME.log") -Append
Write-UpdateEvent 'Update-All start' ([System.Diagnostics.EventLogEntryType]::Information) 6000

$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;$env:PSModulePath"
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Install-PackageProvider NuGet -Force | Out-Null
    Install-Module PSWindowsUpdate -RequiredVersion 2.2.0.3 -Repository PSGallery -Force -Confirm:$false -Scope AllUsers
}
Import-Module PSWindowsUpdate -Force
if (-not (Get-WUServiceManager | Where-Object ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d')) {
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
}

$reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
if (-not (Test-Path $reg)) { New-Item $reg -Force | Out-Null }
Set-ItemProperty $reg DODownloadMode 100 -Type DWord -Force

try { Install-WindowsUpdate -Category 'Servicing Stack Updates' -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue } catch { Write-Warning "Servicing Stack Update install failed: $($_.Exception.Message)" }

function Register-Resume {
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $t = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName 'ResumeUpdateAll' -TaskPath '\Temp\' -Action $a -Trigger $t -Force | Out-Null
}
function Remove-Resume {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    if ($PSCmdlet.ShouldProcess('ResumeUpdateAll', 'Unregister scheduled task')) {
        Unregister-ScheduledTask -TaskName 'ResumeUpdateAll' -TaskPath '\Temp\' -Confirm:$false -ErrorAction SilentlyContinue
    }
}
function Test-PendingReboot {
    # Registry-only fallback for when Get-WURebootStatus (PSWindowsUpdate) throws -
    # same checks used by Uninstall-ezPivCard.ps1 elsewhere in this repo.
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        return $true
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        return $true
    }
    $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                             -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($pfro -and $pfro.PendingFileRenameOperations) { return $true }
    return $false
}
function Test-NeedReboot {
    try { $s = Get-WURebootStatus; return ($s.RebootPending -or $s.WindowsUpdatePending) } catch { try { return (Test-PendingReboot) } catch { return $false } }
}

$resumeCountFile = Join-Path $LogDir 'ResumeCount.txt'
$maxResumeAttempts = 10
$resumeCount = 0
if (Test-Path $resumeCountFile) { $resumeCount = [int](Get-Content $resumeCountFile -ErrorAction SilentlyContinue) }

$loop = $true
# Independent of $maxResumeAttempts above (which caps reboot/resume cycles):
# this catches the case where Install-WindowsUpdate keeps throwing on the
# same KB(s) without a reboot ever becoming pending, which would otherwise
# spin this loop forever since $updates never empties and no reboot ever
# breaks out via the resume-cap path.
$consecutiveFailures = 0
$maxConsecutiveFailures = 5
while ($loop) {
    $installFailedThisPass = $false
    $scanErrors = $null
    $rawUpdates = Get-WindowsUpdate -MicrosoftUpdate -NotCategory 'Upgrades' -IgnoreReboot -AcceptAll -ErrorAction SilentlyContinue -ErrorVariable scanErrors |
        Where-Object { $_.KBArticleIDs }
    $updates = $rawUpdates | Where-Object { -not ($_.KBArticleIDs | Where-Object { $_ -in $SkipKB }) }
    $excludedBySkipKB = $rawUpdates | Where-Object { $_.KBArticleIDs | Where-Object { $_ -in $SkipKB } }
    if ($excludedBySkipKB) { $script:Skipped = $true }

    if ($ForceKB) {
        $missing = $ForceKB | Where-Object { $_ -notin $updates.KBArticleIDs }
        if ($missing) {
            try { Install-WindowsUpdate -KBArticleID $missing -MicrosoftUpdate -AcceptAll -IgnoreReboot } catch { $script:HadErrors = $true; $installFailedThisPass = $true }
        }
    }

    if ($updates) {
        try { Install-WindowsUpdate -Updates $updates -MicrosoftUpdate -AcceptAll -IgnoreReboot } catch { $script:HadErrors = $true; $installFailedThisPass = $true }
    } elseif ($scanErrors) {
        # A real scan failure (WSUS unreachable, PSWindowsUpdate internal
        # error, transient COM failure) leaves $rawUpdates empty - identical
        # to "nothing to install" - so without this check, a failed scan was
        # silently reported as a clean, complete run (exit 0). Route it
        # through the same consecutive-failure counter as a real install
        # failure below instead of falling into the "$loop = $false" done
        # path.
        $script:HadErrors = $true
        $installFailedThisPass = $true
        foreach ($e in $scanErrors) { Write-Warning "Update scan failed: $($e.Exception.Message)" }
    } else {
        $loop = $false
    }

    if ($LogEndpoint) {
        try {
            $payload = @{Computer = $env:COMPUTERNAME; UTC = (Get-Date).ToUniversalTime(); KBs = $updates.KBArticleIDs } | ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri $LogEndpoint -Body $payload -ContentType 'application/json' -TimeoutSec 15
        } catch { Write-Warning "LogEndpoint post failed: $($_.Exception.Message)" }
    }

    if (Test-NeedReboot) {
        $consecutiveFailures = 0
        $resumeCount++
        Set-Content -Path $resumeCountFile -Value $resumeCount
        if ($resumeCount -gt $maxResumeAttempts) {
            Stop-UpdateScript "Exceeded $maxResumeAttempts reboot/resume cycles without completing updates" 2
        }
        Register-Resume
        if ($NoImmediateReboot) {
            Stop-UpdateScript "Reboot required; -NoImmediateReboot set, so leaving the reboot to the caller (resume task is registered)." 3010
        }
        Restart-Computer -Force
    } elseif ($installFailedThisPass) {
        $consecutiveFailures++
        if ($consecutiveFailures -ge $maxConsecutiveFailures) {
            Stop-UpdateScript "Aborting after $maxConsecutiveFailures consecutive update-install failures with no reboot pending" 2
        }
    } else {
        $consecutiveFailures = 0
    }
}
Remove-Item $resumeCountFile -Force -ErrorAction SilentlyContinue

if ($WingetCatchUp) {
    for ($i = 0; $i -lt 3; $i++) {
        try { winget upgrade --all --accept-package-agreements --accept-source-agreements --silent | Out-Null; $wingetOK = $true } catch { $wingetOK = $false }
        if ($wingetOK) { Write-UpdateEvent 'winget upgrade OK' ([System.Diagnostics.EventLogEntryType]::Information) 6001; break } else { Start-Sleep 30 }
    }
}

Remove-Resume
Stop-Transcript
try { $script:Mutex.Dispose() } catch { Write-Warning "Mutex dispose failed: $($_.Exception.Message)" }
if ($script:HadErrors) { $exit = 2 } elseif ($script:Skipped) { $exit = 1 } else { $exit = 0 }
Write-UpdateEvent 'Update-All end' ([System.Diagnostics.EventLogEntryType]::Information) 6006
if (Get-Module -ListAvailable BurntToast) { try { Import-Module BurntToast -ErrorAction SilentlyContinue; New-BurntToastNotification -Text 'Updates applied', 'System may reboot.' -Silent } catch { Write-Warning "BurntToast notification failed: $($_.Exception.Message)" } }
exit $exit
