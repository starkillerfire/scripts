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
    [int]         $RingChunkSize       = 250,
    [int]         $ThrottleLimit,
    [int]         $MaxRetry            = 3,

    # ---------- logging ----------
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
    $AdminCred = New-Object PSCredential ($cm.UserName,
                ($cm.Password | ConvertTo-SecureString -AsPlainText -Force))
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

# ----- ring rollout (chunk by parent OU) --------------------------------------
$SortedTargets = $Targets | Sort-Object { ([ADSI]"LDAP://$_").Parent }, $_
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
    [string] $CentralShare,
    [string] $PSWUVersion,
    [switch] $ExcludeDrivers,
    [switch] $ExcludeFeatureUpgrades,
    [int]    $CatchupHours,
    [int]    $CatchupSpanDays
)
$ErrorActionPreference = 'Stop'

# ---- lightweight local log helper ----
$localLog = "$env:SystemRoot\Temp\WinUpdateSweep_$env:COMPUTERNAME.log"
function Log([string]$m){ (Get-Date -Format 's') + '  ' + $m | Add-Content $localLog }

# ---- transcript ----
$trans = "$env:SystemRoot\Temp\WUTranscript_$([guid]::NewGuid()).log"
Start-Transcript -Path $trans | Out-Null

# ---- registry backup ----
$bkDir = "$env:ProgramData\WinUpdateSweep"
New-Item -ItemType Directory -Path $bkDir -Force | Out-Null
$bkBefore = Join-Path $bkDir 'WU_Before.reg'
$bkAfter  = Join-Path $bkDir 'WU_After.reg'
reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" $bkBefore /y | Out-Null

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
    Log "Installing $($updates.Count) update(s)…"
    $updates | Install-WindowsUpdate -AcceptAll -IgnoreReboot -MicrosoftUpdate `
              -Verbose:$false -ErrorAction Continue
    Log "Installed $($updates.Count) update(s)"
} else {
    Log "No updates required"
}

# ---- reboot if needed ----
if ((Get-WURebootStatus).RebootNeeded) {
    Log "Pending reboot"
    shutdown /r /t 30 /c "PatchSweep updates"
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
reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" $bkAfter /y | Out-Null
reg.exe import $bkBefore | Out-Null
gpupdate /target:computer /force /wait:0 | Out-Null

# ---- registry diff ----
$diff = Compare-Object (Get-Content $bkBefore) (Get-Content $bkAfter)
if ($diff) { Log "WU registry diff:`n$($diff | Out-String)" }

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

# ---- copy transcript & log ----
if (Test-Path $CentralShare) {
    Copy-Item $trans     -Destination (Join-Path $CentralShare "$env:COMPUTERNAME.transcript.log") -Force
    Copy-Item $localLog  -Destination (Join-Path $CentralShare "$env:COMPUTERNAME.summary.log")    -Force
}
Stop-Transcript | Out-Null

# Explicit success marker. Invoke-Command is called synchronously (no
# -AsJob) further down in this script, so what it returns here is plain
# pipeline output, not a Job object - it has no .State property to check.
# Returning this object is what lets the caller in the main loop tell
# completed nodes apart from ones that errored or never returned, by
# matching on the PSComputerName property PowerShell attaches automatically
# to remote output.
[pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Status = 'Completed' }
} # --- end payload

# ========= MAIN loop through rings/chunks ====================================
foreach ($ring in $TargetChunks) {
    $remaining = $ring
    for ($try = 1; $try -le $MaxRetry -and $remaining.Count; $try++) {
        Write-Host "Ring size $($ring.Count) - Attempt $try on $($remaining.Count) node(s)…"

        $cim = New-CimSession -ComputerName $remaining -Credential $AdminCred -ErrorAction SilentlyContinue
        $cimFailed = $remaining | Where-Object { $_ -notin ($cim | Select-Object -ExpandProperty ComputerName) }
        foreach ($c in $cimFailed) {
            Write-Warning "Ring attempt $try : could not establish a CIM session to $c"
        }

        $job = Invoke-Command -CimSession $cim -ScriptBlock $RemotePayload -ArgumentList `
               $CentralLogShare,$PSWUVersion,$NoDrivers,$NoFeatureUpgrades,`
               $OffLineCatchupHours,$OffLineCatchupSpan -ErrorAction SilentlyContinue

        # $job holds the [pscustomobject] each node returns at the end of
        # $RemotePayload. Nodes that errored partway through, or never made
        # it that far, simply won't have an entry here - there's no
        # separate error bucket to check.
        $completedComputers = $job | Select-Object -ExpandProperty PSComputerName -Unique

        foreach ($s in $cim) {
            $state = if ($s.ComputerName -in $completedComputers) { 'Completed' } else { 'Failed' }

            $JobsSummary.Add([pscustomobject]@{
                ComputerName = $s.ComputerName
                State        = $state
                Attempt      = $try
            })
        }
        foreach ($c in $cimFailed) {
            $JobsSummary.Add([pscustomobject]@{
                ComputerName = $c
                State        = 'Failed'
                Attempt      = $try
            })
        }

        $remaining = $JobsSummary |
                     Where-Object { $_.State -ne 'Completed' -and $_.Attempt -eq $try } |
                     Select-Object -ExpandProperty ComputerName -Unique

        Remove-CimSession $cim
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
