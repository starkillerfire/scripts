#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LogDir='C:\ProgramData\UpdateAll\Logs',
    [int]$MinFreeGB=8,
    [string[]]$SkipKB=@(),
    [string[]]$ForceKB=@(),
    [string]$PatchWindow='',
    [string]$ConfigPath='C:\ProgramData\UpdateAll\config.json',
    [string]$SelfUpdateSource='',
    [string]$ExpectedSha256='',
    [string]$LogEndpoint='',
    [switch]$WingetCatchUp,
    [switch]$IgnoreBattery,
    [switch]$EnableVerbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$VerbosePreference=if($EnableVerbose.IsPresent){'Continue'}else{'SilentlyContinue'}
$script:HadErrors=$false
$script:Skipped=$false

if(Test-Path $ConfigPath){
    try{
        $cfg=Get-Content $ConfigPath -Raw|ConvertFrom-Json
        foreach($p in $PSBoundParameters.Keys){
            if($cfg.PSObject.Properties[$p]){Set-Variable -Name $p -Value $cfg.$p -Force}
        }
    }catch{}
}

function Write-UpdateEvent{
    param([string]$m,[System.Diagnostics.EventLogEntryType]$t,[int]$id)
    if(-not[Diagnostics.EventLog]::SourceExists('Update-All')){New-EventLog Application 'Update-All'}
    Write-EventLog Application 'Update-All' $t $id $m
}

function Stop-UpdateScript{
    param([string]$m,[int]$code)
    if($code -ne 0){$script:HadErrors=$true}
    Write-Warning $m
    $type=if($code -eq 0){[System.Diagnostics.EventLogEntryType]::Information}elseif($code -eq 1){[System.Diagnostics.EventLogEntryType]::Warning}else{[System.Diagnostics.EventLogEntryType]::Error}
    Write-UpdateEvent $m $type 6000
    try{Stop-Transcript}catch{}
    try{$script:Mutex.ReleaseMutex()}catch{}
    exit $code
}

$script:Mutex=[Threading.Mutex]::new($false,'Global\UpdateAll23H2',[ref]$lockOK)
if(-not$lockOK){exit 0}

function Test-IsAdministrator{
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(-not(Test-IsAdministrator)){
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;exit
}

if($SelfUpdateSource){
    # ExpectedSha256 here is checked against THIS running script, not the
    # download - it's there to make sure the copy currently executing
    # hasn't been tampered with before it's trusted to fetch its own
    # replacement. Refusing to proceed without it means a compromised or
    # MITM'd SelfUpdateSource can't get unverified code to run just because
    # nobody bothered to set the parameter. The replacement script itself
    # can't be hash-pinned the same way since its hash legitimately changes
    # with every release, so that one is checked via Authenticode below
    # instead.
    if(-not $ExpectedSha256){Stop-UpdateScript 'SelfUpdateSource set without ExpectedSha256 - refusing to self-update unverified code' 2}
    try{
        $curHash=(Get-FileHash $PSCommandPath -Algorithm SHA256).Hash
        if($ExpectedSha256 -ne $curHash){Stop-UpdateScript 'SHA256 mismatch' 2}
        $tmp="$env:TEMP\UpdateAll_latest.ps1"
        if($SelfUpdateSource -match '^https?://'){Invoke-WebRequest $SelfUpdateSource -OutFile $tmp -UseBasicParsing -TimeoutSec 30}
        else{Copy-Item $SelfUpdateSource $tmp -Force}
        $newHash=(Get-FileHash $tmp -Algorithm SHA256).Hash
        if($newHash -ne $curHash){
            $sig=Get-AuthenticodeSignature $tmp
            if($sig.Status -ne 'Valid'){
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                Stop-UpdateScript "Self-update package failed Authenticode validation (status: $($sig.Status)) - refusing to run it" 2
            }
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`""
            exit
        }else{Remove-Item $tmp -Force}
    }catch{}
}

$freeGB=[math]::Round((Get-PSDrive C).Free/1GB,1)
if($freeGB -lt $MinFreeGB){Stop-UpdateScript "Low disk" 2}

if(-not$IgnoreBattery){
    $bat=Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if($bat -and $bat.BatteryStatus -ne 2){Stop-UpdateScript 'On battery' 2}
}

function Test-UpdateWindow{
    param([string]$Spec)
    if(-not$Spec){return $true}
    $now=Get-Date
    $day=$now.ToString('ddd',[CultureInfo]::InvariantCulture)
    foreach($s in $Spec -split ';'){
        if($s -match '^\s*(?<d>[A-Za-z,-]+)\s+(?<a>\d\d:\d\d)-(?<b>\d\d:\d\d)\s*$'){
            if(($matches.d -split ',') -contains $day){
                $A=[DateTime]::ParseExact($matches.a,'HH:mm',$null)
                $B=[DateTime]::ParseExact($matches.b,'HH:mm',$null)
                $start=$now.Date.AddHours($A.Hour).AddMinutes($A.Minute)
                $end=$now.Date.AddHours($B.Hour).AddMinutes($B.Minute)
                if($end -le $start){$end=$end.AddDays(1)}
                if($now -ge $start -and $now -lt $end){return $true}
            }
        }
    }
    return $false
}
# Wait for the patch window with a 12-hour hard cap to prevent infinite blocking
$patchWindowDeadline = (Get-Date).AddHours(12)
while(-not(Test-UpdateWindow $PatchWindow)){
    if((Get-Date) -gt $patchWindowDeadline){ Stop-UpdateScript 'Patch window wait exceeded 12 hours' 2 }
    Start-Sleep 900
}

New-Item $LogDir -ItemType Directory -Force|Out-Null
Start-Transcript -Path (Join-Path $LogDir "UpdateAll-$env:COMPUTERNAME.log") -Append
Write-UpdateEvent 'Update-All start' ([System.Diagnostics.EventLogEntryType]::Information) 6000

if((([Net.ServicePointManager]::SecurityProtocol)-band 3072)-eq 0){[Net.ServicePointManager]::SecurityProtocol+=3072}

$env:PSModulePath="C:\Program Files\WindowsPowerShell\Modules;$env:PSModulePath"
if(-not(Get-Module -ListAvailable PSWindowsUpdate)){
    Install-PackageProvider NuGet -Force|Out-Null
    Install-Module PSWindowsUpdate -MinimumVersion 2.2.0.3 -Force -Confirm:$false -Scope AllUsers
}
Import-Module PSWindowsUpdate -Force
if(-not(Get-WUServiceManager|Where-Object ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d')){
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false|Out-Null
}

$reg='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
if(-not(Test-Path $reg)){New-Item $reg -Force|Out-Null}
Set-ItemProperty $reg DODownloadMode 100 -Type DWord -Force

try{Install-WindowsUpdate -Category 'Servicing Stack Updates' -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue}catch{}

function Register-Resume{
    $a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $t=New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName 'ResumeUpdateAll' -TaskPath '\Temp\' -Action $a -Trigger $t -Force|Out-Null
}
function Remove-Resume{Unregister-ScheduledTask -TaskName 'ResumeUpdateAll' -TaskPath '\Temp\' -Confirm:$false -ErrorAction SilentlyContinue}
function NeedReboot{
    try{$s=Get-WURebootStatus;return($s.RebootPending -or $s.WindowsUpdatePending)}catch{try{return(Test-PendingReboot)}catch{return $false}}
}

$resumeCountFile=Join-Path $LogDir 'ResumeCount.txt'
$maxResumeAttempts=10
$resumeCount=0
if(Test-Path $resumeCountFile){$resumeCount=[int](Get-Content $resumeCountFile -ErrorAction SilentlyContinue)}

$loop=$true
while($loop){
    $rawUpdates=Get-WindowsUpdate -MicrosoftUpdate -NotCategory 'Upgrades' -IgnoreReboot -AcceptAll -ErrorAction SilentlyContinue|
                Where-Object{$_.KBArticleIDs}
    $updates=$rawUpdates|Where-Object{-not($_.KBArticleIDs|Where-Object{$_ -in $SkipKB})}
    $excludedBySkipKB=$rawUpdates|Where-Object{$_.KBArticleIDs|Where-Object{$_ -in $SkipKB}}
    if($excludedBySkipKB){$script:Skipped=$true}

    if($ForceKB){
        $missing=$ForceKB|Where-Object{$_ -notin $updates.KBArticleIDs}
        if($missing){
            try{Install-WindowsUpdate -KBArticleID $missing -MicrosoftUpdate -AcceptAll -IgnoreReboot}catch{$script:HadErrors=$true}
        }
    }

    if($updates){
        try{Install-WindowsUpdate -Updates $updates -MicrosoftUpdate -AcceptAll -IgnoreReboot}catch{$script:HadErrors=$true}
    }else{
        $loop=$false
    }

    if($LogEndpoint){
        try{
            $payload=@{Computer=$env:COMPUTERNAME;UTC=(Get-Date).ToUniversalTime();KBs=$updates.KBArticleIDs}|ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri $LogEndpoint -Body $payload -ContentType 'application/json' -TimeoutSec 15
        }catch{}
    }

    if(NeedReboot){
        $resumeCount++
        Set-Content -Path $resumeCountFile -Value $resumeCount
        if($resumeCount -gt $maxResumeAttempts){
            Stop-UpdateScript "Exceeded $maxResumeAttempts reboot/resume cycles without completing updates" 2
        }
        Register-Resume
        Restart-Computer -Force
    }
}
Remove-Item $resumeCountFile -Force -ErrorAction SilentlyContinue

if($WingetCatchUp){
    for($i=0;$i -lt 3;$i++){
        try{winget upgrade --all --accept-package-agreements --accept-source-agreements --silent|Out-Null;$wingetOK=$true}catch{$wingetOK=$false}
        if($wingetOK){Write-UpdateEvent 'winget upgrade OK' ([System.Diagnostics.EventLogEntryType]::Information) 6001;break}else{Start-Sleep 30}
    }
}

Remove-Resume
Stop-Transcript
$script:Mutex.ReleaseMutex()
if($script:HadErrors){$exit=2}elseif($script:Skipped){$exit=1}else{$exit=0}
Write-UpdateEvent 'Update-All end' ([System.Diagnostics.EventLogEntryType]::Information) 6006
if(Get-Module -ListAvailable BurntToast){try{Import-Module BurntToast -ErrorAction SilentlyContinue;New-BurntToastNotification -Text 'Updates applied','System may reboot.' -Silent}catch{}}
exit $exit
