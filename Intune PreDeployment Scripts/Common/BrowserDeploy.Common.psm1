<#
.SYNOPSIS
    Shared helpers for the browser deployment scripts in this folder
    (installChrome.ps1, Edge.ps1) - single-instance locking, adaptive BITS
    downloads with hash verification, and event-log-backed logging.

.DESCRIPTION
    installChrome.ps1 and Edge.ps1 each reimplemented their own version of
    these four things, and had already started to drift apart in the
    process (different lock modes, different BITS state-polling, etc.) -
    this module is the single place that logic lives now, so a fix applies
    to both scripts instead of just whichever one someone happened to be
    editing.
#>

Set-StrictMode -Version Latest

# Cache which event sources have already been registered this process, so
# Write-DeployLog doesn't re-check [Diagnostics.EventLog]::SourceExists on
# every single call.
$script:RegisteredEventSources = @{}

function New-SingleInstanceLock {
    <#
    .SYNOPSIS
        Opens an exclusive lock file, returning the FileStream on success or
        $null if another instance already holds it.
    .DESCRIPTION
        Always uses FileMode.CreateNew, which atomically fails if the file
        already exists and is still open elsewhere - this is the correct
        primitive for a single-instance lock. (One of these two scripts used
        to use OpenOrCreate instead, which is less strict about excluding
        concurrent access.)
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        return [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch {
        return $null
    }
}

function Close-SingleInstanceLock {
    param(
        [Parameter(Mandatory)][AllowNull()][System.IO.FileStream]$LockStream,
        [Parameter(Mandatory)][string]$Path
    )
    if ($LockStream) {
        try { $LockStream.Close() } catch {}
    }
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
}

function Get-AdaptiveBitsPriority {
    <#
    .SYNOPSIS
        Picks a BITS transfer priority based on current network conditions.
    .PARAMETER CheckVpn
        When set, treats an active VPN adapter as "prefer foreground" before
        falling back to the throughput-based heuristic - useful for
        deployments that run over VPN links where background transfers can
        stall for a long time.
    #>
    param(
        [switch]$CheckVpn,
        [int]$LowThroughputBytesPerSec = 2500000
    )

    if ($CheckVpn) {
        $isVpn = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match 'VPN' -or $_.Name -match 'VPN' }
        if ($isVpn) { return 'Foreground' }
    }

    $rx = (Get-NetAdapterStatistics -ErrorAction SilentlyContinue |
           Sort-Object ReceivedBytes -Descending |
           Select-Object -First 1).ReceivedBytes
    if ($rx -lt $LowThroughputBytesPerSec) { 'Background' } else { 'High' }
}

function Invoke-VerifiedDownload {
    <#
    .SYNOPSIS
        Downloads a file via BITS (falling back to Invoke-WebRequest),
        verifies its SHA-256 hash when supplied, and retries with backoff.
    .PARAMETER LogAction
        Scriptblock invoked as { param($Message, $Level) ... } for each
        retry/warning - lets the caller route messages through its own
        Write-Log function (with its own event source/IDs) instead of this
        module owning logging concerns it has no context for.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Sha256,
        [string]$Proxy,
        [switch]$NoHashCheck,
        [switch]$NoResume,
        [int]$MaxAttempts = 3,
        [switch]$CheckVpnForBitsPriority,
        [scriptblock]$LogAction = { param($Message, $Level) Write-Verbose $Message }
    )

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            if ($NoResume -and (Test-Path $Destination)) { Remove-Item $Destination -Force }

            try {
                Import-Module BitsTransfer -ErrorAction Stop
                $bitsArgs = @{
                    Source       = $Url
                    Destination  = $Destination
                    Priority     = (Get-AdaptiveBitsPriority -CheckVpn:$CheckVpnForBitsPriority)
                    Asynchronous = $true
                }
                if ($Proxy) { $bitsArgs.ProxyUsage = 'Override'; $bitsArgs.ProxyList = $Proxy }
                else { $bitsArgs.ProxyUsage = 'AutoDetect' }
                $job = Start-BitsTransfer @bitsArgs

                # Poll every state that still means "in progress" - checking
                # only for 'Transferring' exits this loop too early while a
                # job is still Queued/Connecting, leaving the transfer
                # incomplete when Complete-BitsTransfer runs right after.
                $activeStates = @('Transferring', 'Queued', 'Connecting', 'TransientError', 'Suspended')
                while ($job.JobState -in $activeStates) {
                    Start-Sleep -Seconds 3
                    if ($job.JobState -eq 'TransientError') { Resume-BitsTransfer -BitsJob $job }
                    elseif ($job.JobState -eq 'Suspended') {
                        $metered = (Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.IsConnected }).IsMetered
                        if (-not $metered) { Resume-BitsTransfer -BitsJob $job }
                    }
                }
                if ($job.JobState -eq 'Error') {
                    Remove-BitsTransfer -BitsJob $job
                    throw "BITS transfer failed: $($job.ErrorDescription)"
                }
                Complete-BitsTransfer -BitsJob $job
            } catch {
                & $LogAction "BITS unavailable/failed ($($_.Exception.Message)) - falling back to Invoke-WebRequest." 'Warning'
                $iw = @{ Uri = $Url; OutFile = $Destination; UseBasicParsing = $true; ErrorAction = 'Stop' }
                if ($Proxy) { $iw.Proxy = $Proxy }
                Invoke-WebRequest @iw
            }

            if (-not $NoHashCheck -and $Sha256) {
                $calc = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash.ToUpperInvariant()
                if ($calc -ne $Sha256.ToUpperInvariant()) { throw 'Hash mismatch' }
            }
            return
        } catch {
            & $LogAction "Download attempt $i of $MaxAttempts failed: $_" 'Warning'
            if ($i -eq $MaxAttempts) { throw }
            Start-Sleep -Seconds ([int][math]::Pow(2, $i))
        }
    }
}

function Write-DeployLog {
    <#
    .SYNOPSIS
        Writes a message to the console/transcript and the Application
        event log, registering the event source on first use.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$EventSource,
        [int]$EventId = 1000,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "$stamp - $Message"

    switch ($Level) {
        'Error'   { Write-Verbose $line; Write-Error $line -ErrorAction Continue }
        'Warning' { Write-Warning $line }
        default   { Write-Verbose $line }
    }
    Write-Information $line -InformationAction Continue

    try {
        if (-not $script:RegisteredEventSources.ContainsKey($EventSource)) {
            if (-not [Diagnostics.EventLog]::SourceExists($EventSource)) {
                New-EventLog -LogName Application -Source $EventSource
            }
            $script:RegisteredEventSources[$EventSource] = $true
        }
        Write-EventLog -LogName Application -Source $EventSource -EntryType $Level -EventId $EventId -Message $Message -ErrorAction SilentlyContinue
    } catch {}
}

Export-ModuleMember -Function New-SingleInstanceLock, Close-SingleInstanceLock, Get-AdaptiveBitsPriority, Invoke-VerifiedDownload, Write-DeployLog
