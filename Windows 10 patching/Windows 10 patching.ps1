<# =======================================================================
 Invoke-FleetPatchSweep.ps1
 -------------------------------------------------------------------------
 Enterprise patch sweep with MU-flip + WSUS rollback, retry logic,
 CIM sessions, offline catch-up task, central logging, and a
 local run-summary file. 100 % Windows PowerShell 5.1 compatible:
 • No JSON config
 • No Azure / Log Analytics
 • No PS 7 null-coalescing or ternary operators
 ======================================================================= #>

[CmdletBinding()]
param(
    # ---------- target selection ----------
    [string[]]    $ComputerName,
    [string]      $ComputerListCsv,
    [string]      $OU,
    [switch]      $SkipOffline,

    # ---------- behaviour ----------
    [switch]      $NoDrivers,
    [switch]      $NoFeatureUpgrades,
    [switch]      $NoAutoReboot,
    [int]         $RingChunkSize       = 250,
    [int]         $ThrottleLimit,
    [int]         $MaxRetry            = 3,

    # Safety valve for FIX 1: resolving an -OU/-CSV that unexpectedly
    # expands to a huge machine list must not silently patch-and-reboot
    # every match. Above this count, an explicit typed confirmation is
    # required before the fleet loop starts.
    [int]         $MaxTargets          = 50,

    # ---------- logging ----------
    # Placeholder path - update for this site, or pass -CentralLogShare.
    # An unreachable share already fails loudly below (Test-Path check),
    # so this won't silently skip logging if left unconfigured.
    [string]      $CentralLogShare     = "\\fileserver\PatchLogs",

    # ---------- credentials ----------
    [pscredential]$Credential,
    [string]      $CMTarget            # name in Windows Credential Manager
)

# -------- constants --------
$PSWUVersion         = '2.2.1.4'
$OffLineCatchupHours = 8
$OffLineCatchupSpan  = 2   # days
$LogRetentionDays    = 30
$NowTag              = (Get-Date -Format 'yyyyMMdd_HHmmss')
$JobsSummary         = [System.Collections.Generic.List[psobject]]::new()

# =====  Credential ============================================================
if ($Credential) {
    $AdminCred = $Credential
}
elseif ($CMTarget) {
    $cm = Get-StoredCredential -Target $CMTarget
    if (-not $cm) { throw "Credential '$CMTarget' not found in Credential Manager." }
    # $cm.Password from the CredentialManager module is already a
    # SecureString, not plaintext - piping it into ConvertTo-SecureString
    # -AsPlainText (which expects a String) threw a type-binding error
    # before any target was ever touched. It can be used directly.
    $AdminCred = New-Object PSCredential ($cm.UserName, $cm.Password)
}
else {
    $AdminCred = Get-Credential -Message "Admin creds for target machines"
}

# =====  Build target list =====================================================
function Get-Targets {
    param(
        [string[]] $Inline,
        [string]   $CsvPath,
        [string]   $OUPath,
        [switch]   $SkipOffline
    )
    $all = @()
    if ($Inline)  { $all += $Inline }
    if ($CsvPath) { $all += (Import-Csv $CsvPath).ComputerName }
    if ($OUPath)  {
        $all += Get-ADComputer -SearchBase $OUPath -Filter * -Properties DNSHostName |
               Select-Object -ExpandProperty DNSHostName
    }
    if (-not $all) { throw "No computer list supplied." }
    $uniq = $all | Sort-Object -Unique

    if ($SkipOffline) {
        $online  = $uniq | Where-Object { Test-Connection $_ -Quiet -Count 1 }
        $offline = $uniq | Where-Object { $_ -notin $online }
        if ($offline) { Write-Warning "Skipping offline: $($offline -join ', ')" }
        return ,$online
    }
    return ,$uniq
}

$Targets = Get-Targets -Inline $ComputerName -CsvPath $ComputerListCsv -OUPath $OU -SkipOffline:$SkipOffline
if (-not $Targets) { Write-Host "Nothing to do."; return }

# ----- FIX 1: sanity check + explicit confirmation for large blast radius ----
# An -OU/-CSV that resolves to far more machines than intended must not
# silently patch-and-reboot the whole list. Above -MaxTargets, require a
# typed confirmation before the fleet loop below starts. $PSCmdlet.ShouldContinue()
# was considered, but it throws outright (rather than degrading safely) when the
# host can't prompt (e.g. unattended/SYSTEM context) - a plain Read-Host with an
# explicit non-interactive check fails closed instead, which is the safer
# default for a run that patches and reboots real machines.
if ($Targets.Count -gt $MaxTargets) {
    Write-Warning "Resolved target list contains $($Targets.Count) computer(s), which exceeds the safety threshold of $MaxTargets (see -MaxTargets to raise it). This run will patch AND REBOOT every matched machine."
    if (-not [Environment]::UserInteractive) {
        throw "Aborting: $($Targets.Count) resolved target(s) exceeds -MaxTargets ($MaxTargets) and this session is non-interactive, so explicit confirmation cannot be collected. Re-run interactively to confirm, or pass a higher -MaxTargets if this scale is intentional."
    }
    $confirmation = Read-Host "Type YES to confirm patching and rebooting $($Targets.Count) machine(s)"
    if ($confirmation -ne 'YES') {
        Write-Warning "Aborted: confirmation not received for a $($Targets.Count)-machine run."
        return
    }
}

# ----- ring rollout (chunk by parent OU) --------------------------------------
# A bare computer name is not a valid ADSI path - "LDAP://PC123" isn't
# resolvable and throws, so this has to go through Get-ADComputer first to
# get an actual distinguishedName before binding. Falls back to leaving the
# targets in their original order (no OU grouping) if the ActiveDirectory
# module isn't available or a given name doesn't resolve, rather than
# failing the whole ring rollout over one bad/non-domain name.
function Get-PatchTargetOuParent {
    param([string]$ComputerName)
    try {
        $dn = (Get-ADComputer -Identity $ComputerName -ErrorAction Stop).DistinguishedName
        return ([ADSI]"LDAP://$dn").Parent
    } catch {
        return ''
    }
}
if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
    # The second sort key was a bare `$_` outside any per-item scriptblock, so
    # it wasn't bound to the pipeline item at sort time and the intended
    # tie-break by computer name was silently a no-op. Wrapping it in its own
    # scriptblock makes Sort-Object evaluate it per-item like the first key.
    $SortedTargets = $Targets | Sort-Object { Get-PatchTargetOuParent -ComputerName $_ }, { $_ }
} else {
    Write-Warning 'ActiveDirectory module not available - skipping OU-based ring ordering.'
    $SortedTargets = $Targets
}
$TargetChunks  = for ($i = 0; $i -lt $SortedTargets.Count; $i += $RingChunkSize) {
    ,($SortedTargets[$i..([math]::Min($i + $RingChunkSize - 1,
                                      $SortedTargets.Count - 1))])
}

# =====  PSWindowsUpdate module pin ============================================
if (-not (Get-Module -ListAvailable PSWindowsUpdate |
          Where-Object Version -eq $PSWUVersion)) {
    Install-Module PSWindowsUpdate -RequiredVersion $PSWUVersion -Force -Confirm:$false
}
Import-Module PSWindowsUpdate -RequiredVersion $PSWUVersion

# =====  House-keeping on central share =======================================
if (-not (Test-Path $CentralLogShare)) {
    throw "Central log share $CentralLogShare unreachable."
}
Get-ChildItem $CentralLogShare -Filter '*.log' |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# =====  Remote payload ========================================================
$RemotePayload = {
param(
    [string] $PSWUVersion,
    [switch] $ExcludeDrivers,
    [switch] $ExcludeFeatureUpgrades,
    [switch] $SuppressReboot,
    [int]    $CatchupHours,
    [int]    $CatchupSpanDays
)
$ErrorActionPreference = 'Stop'

# ---- lightweight local log helper ----
$localLog = "$env:SystemRoot\Temp\WinUpdateSweep_$env:COMPUTERNAME.log"
function Write-Log([string]$m){ (Get-Date -Format 's') + '  ' + $m | Add-Content $localLog }

# ---- transcript ----
$trans = "$env:SystemRoot\Temp\WUTranscript_$([guid]::NewGuid()).log"
Start-Transcript -Path $trans | Out-Null

# ---- registry backup ----
$bkDir = "$env:ProgramData\WinUpdateSweep"
New-Item -ItemType Directory -Path $bkDir -Force | Out-Null
$bkBefore = Join-Path $bkDir 'WU_Before.reg'
$bkAfter  = Join-Path $bkDir 'WU_After.reg'
$wuKeyPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
reg.exe export $wuKeyPath $bkBefore /y | Out-Null
# On a machine with no WSUS/GPO-managed WindowsUpdate key (common off a
# WSUS-governed network), reg.exe export fails and $bkBefore never gets
# created - tracked here so the rollback import and registry diff below
# can skip cleanly instead of throwing on a missing file (which would
# abort this whole remote payload under $ErrorActionPreference = 'Stop').
$bkBeforeOk = ($LASTEXITCODE -eq 0) -and (Test-Path $bkBefore)
if (-not $bkBeforeOk) {
    Write-Log "WARNING: could not export '$wuKeyPath' before the MU flip (key may not exist) - WSUS rollback will be skipped for this node."
}

# ---- module pin ----
if (-not (Get-Module -ListAvailable PSWindowsUpdate |
          Where-Object Version -eq $PSWUVersion)) {
    Install-Module PSWindowsUpdate -RequiredVersion $PSWUVersion -Force -Confirm:$false
}
Import-Module PSWindowsUpdate -RequiredVersion $PSWUVersion

# ---- enable MU ----
Set-PSWUSettings -MicrosoftUpdate $true -Confirm:$false

# ---- choose update categories ----
if ($ExcludeDrivers) {
    $cats = @('Software')
} else {
    $cats = @('Software','Driver')
}

# ---- feature-upgrade filter ----
if ($ExcludeFeatureUpgrades) {
    $filterScript = { $_.Title -notmatch 'Feature update to Windows' }
} else {
    $filterScript = { $true }
}

# ---- scan & install ----
$criteria = 'IsInstalled=0 and IsAssigned=1'
$updates  = Get-WindowsUpdate -Criteria $criteria -Category $cats -MicrosoftUpdate -Verbose:$false |
            Where-Object $filterScript

if ($updates) {
    Write-Log "Installing $($updates.Count) update(s)…"
    $updates | Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate `
              -Verbose:$false -ErrorAction Continue
    Write-Log "Installed $($updates.Count) update(s)"
} else {
    Write-Log "No updates required"
}

# ---- reboot if needed ----
if ((Get-WURebootStatus).RebootNeeded) {
    Write-Log "Pending reboot"
    if ($SuppressReboot) {
        Write-Log "Reboot suppressed by -NoAutoReboot - node stays pending until the offline catch-up task or a manual restart."
    } else {
        # FIX 2: 30 seconds gave logged-in users essentially no real notice
        # before the machine restarted. Lengthened to 5 minutes; /c already
        # surfaces a message via the built-in shutdown warning dialog.
        shutdown /r /t 300 /c "PatchSweep: this computer will restart in 5 minutes to finish installing updates. Save your work now."
    }
}

# Roll back the MU flip set earlier in this payload (Set-PSWUSettings
# -MicrosoftUpdate $true). The whole point of flipping to Microsoft Update
# was to opportunistically pick up updates/drivers WSUS hasn't approved yet
# for this one scan-and-install pass; once that's done, control needs to
# go back to WSUS/GPO so it keeps governing the machine between sweeps
# instead of fighting with whatever Group Policy expects. This import runs
# unconditionally, on every sweep, regardless of whether the install above
# succeeded - it is the "WSUS rollback" half of the MU-flip+WSUS-rollback
# design described at the top of this script, not a failure-only recovery
# step.
reg.exe export $wuKeyPath $bkAfter /y | Out-Null
if ($bkBeforeOk) {
    reg.exe import $bkBefore | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Log "WARNING: reg.exe import of pre-flip WindowsUpdate settings failed (exit $LASTEXITCODE)." }
} else {
    Write-Log "Skipping WSUS rollback import - no pre-flip backup was captured."
}
gpupdate /target:computer /force /wait:0 | Out-Null

# ---- registry diff ----
if ($bkBeforeOk -and (Test-Path $bkAfter)) {
    $diff = Compare-Object (Get-Content $bkBefore) (Get-Content $bkAfter)
    if ($diff) { Write-Log "WU registry diff:`n$($diff | Out-String)" }
}

# ---- offline catch-up task ----
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition Interval="PT${CatchupHours}H" Duration="P${CatchupSpanDays}D"/>
      <StartBoundary>$(Get-Date -Format s)</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="System"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
  <Actions Context="System">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoLogo -NoProfile -WindowStyle Hidden -Command "& { Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -MicrosoftUpdate }"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
$taskPath = "$env:SystemRoot\Temp\PatchSweepCatchup.xml"
$taskXml | Out-File -Encoding unicode $taskPath
schtasks /Create /TN "PatchSweepCatchup" /XML $taskPath /RU SYSTEM /F | Out-Null
Remove-Item $taskPath -Force

# ---- stop transcript ----
# FIX 3: the central log share copy used to happen right here, inside the
# remote session - but that's a third hop (controller -> this machine -> file
# server) that WinRM can't authenticate without CredSSP/delegation, which
# isn't configured. So this payload no longer touches $CentralShare at all;
# it just leaves the transcript/log on this machine and hands their paths
# back to the caller. The controller (which already holds normal credentials
# for the file share) does the actual copy to $CentralShare after this
# Invoke-Command call returns - see the main loop below.
Stop-Transcript | Out-Null

# Explicit success marker. Invoke-Command is called synchronously (no
# -AsJob) further down in this script, so what it returns here is plain
# pipeline output, not a Job object - it has no .State property to check.
# Returning this object is what lets the caller in the main loop tell
# completed nodes apart from ones that errored or never returned, by
# matching on the PSComputerName property PowerShell attaches automatically
# to remote output. TranscriptPath/LocalLogPath let the controller pull the
# files back over the existing PSSession (Copy-Item -FromSession) and then
# copy them on to $CentralShare itself.
[pscustomobject]@{
    ComputerName   = $env:COMPUTERNAME
    Status         = 'Completed'
    TranscriptPath = $trans
    LocalLogPath   = $localLog
}
} # --- end payload

# ========= MAIN loop through rings/chunks ====================================
foreach ($ring in $TargetChunks) {
    $remaining = $ring
    for ($try = 1; $try -le $MaxRetry -and $remaining.Count; $try++) {
        Write-Host "Ring size $($ring.Count) - Attempt $try on $($remaining.Count) node(s)…"

        # Invoke-Command has no -CimSession parameter at all (CIM sessions
        # are for Get-CimInstance/Invoke-CimMethod, not PowerShell
        # remoting) - this used to throw a parameter-binding error on every
        # single attempt, so the remote patch step never actually ran on
        # any node. Real PSSessions are what Invoke-Command needs here.
        $session = New-PSSession -ComputerName $remaining -Credential $AdminCred -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue
        $sessionFailed = $remaining | Where-Object { $_ -notin ($session | Select-Object -ExpandProperty ComputerName) }
        foreach ($c in $sessionFailed) {
            Write-Warning "Ring attempt $try : could not establish a PS session to $c"
        }

        $job = Invoke-Command -Session $session -ScriptBlock $RemotePayload -ArgumentList `
               $PSWUVersion,$NoDrivers,$NoFeatureUpgrades,$NoAutoReboot,`
               $OffLineCatchupHours,$OffLineCatchupSpan -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue

        # $job holds the [pscustomobject] each node returns at the end of
        # $RemotePayload. Nodes that errored partway through, or never made
        # it that far, simply won't have an entry here - there's no
        # separate error bucket to check.
        $completedComputers = $job | Select-Object -ExpandProperty PSComputerName -Unique

        foreach ($s in $session) {
            $state = if ($s.ComputerName -in $completedComputers) { 'Completed' } else { 'Failed' }

            # FIX 3 (continued): pull the transcript/log back from the remote
            # machine over the already-authenticated PSSession, then copy
            # them on to $CentralShare using the controller's own
            # credentials - avoiding the double-hop that failed when this
            # copy ran inside the remote session.
            if ($state -eq 'Completed') {
                $result = $job | Where-Object { $_.PSComputerName -eq $s.ComputerName } | Select-Object -First 1
                if ($result -and $result.TranscriptPath -and $result.LocalLogPath) {
                    try {
                        $localTemp = Join-Path $env:TEMP "PatchSweep_$($s.ComputerName)"
                        New-Item -ItemType Directory -Path $localTemp -Force | Out-Null

                        Copy-Item -FromSession $s -Path $result.TranscriptPath -Destination $localTemp -Force -ErrorAction Stop
                        Copy-Item -FromSession $s -Path $result.LocalLogPath   -Destination $localTemp -Force -ErrorAction Stop

                        $localTrans = Join-Path $localTemp (Split-Path $result.TranscriptPath -Leaf)
                        $localSumm  = Join-Path $localTemp (Split-Path $result.LocalLogPath   -Leaf)

                        Copy-Item -Path $localTrans -Destination (Join-Path $CentralLogShare "$($s.ComputerName).transcript.log") -Force -ErrorAction Stop
                        Copy-Item -Path $localSumm  -Destination (Join-Path $CentralLogShare "$($s.ComputerName).summary.log")    -Force -ErrorAction Stop
                    } catch {
                        Write-Warning "Could not copy logs for $($s.ComputerName) to central share ${CentralLogShare}: $($_.Exception.Message)"
                    }
                }
            }

            $JobsSummary.Add([pscustomobject]@{
                ComputerName = $s.ComputerName
                State        = $state
                Attempt      = $try
            })
        }
        foreach ($c in $sessionFailed) {
            $JobsSummary.Add([pscustomobject]@{
                ComputerName = $c
                State        = 'Failed'
                Attempt      = $try
            })
        }

        $remaining = $JobsSummary |
                     Where-Object { $_.State -ne 'Completed' -and $_.Attempt -eq $try } |
                     Select-Object -ExpandProperty ComputerName -Unique

        Remove-PSSession $session
    }
}

# ========= local summary file ===============================================
$nonOk      = $JobsSummary | Where-Object State -ne 'Completed' |
              Select-Object -ExpandProperty ComputerName -Unique
$summaryTxt = "PatchSweepSummary_$NowTag.txt"
$summary    = @(
  "PatchSweep run: $NowTag"
  "------------------------------------------"
  "Total targets : $($Targets.Count)"
  "Completed     : $($Targets.Count - $nonOk.Count)"
  "Non-compliant : $($nonOk.Count)"
  ""
)
if ($nonOk) {
    $summary += "List of non-compliant nodes:"
    $summary += $nonOk
}
$summary | Set-Content -Encoding utf8 $summaryTxt

Write-Host "Finished - summary written to $(Join-Path (Get-Location) $summaryTxt)"
Write-Host "Per-node transcripts and summaries copied to $CentralLogShare"
