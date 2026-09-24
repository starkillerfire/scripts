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

# Enforce TLS 1.2+ here rather than trusting every caller to set it before
# importing this module - Edge.ps1 currently does, but that made it a silent
# footgun for any future caller (e.g. installChrome.ps1, if it's ever moved
# onto this module) that doesn't.
if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

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
    <#
    .SYNOPSIS
        Releases a lock taken by New-SingleInstanceLock and removes the lock
        file.
    .DESCRIPTION
        Accepts a $null stream so callers can release unconditionally in a
        finally block without first checking whether the lock was actually
        acquired. Closing the stream and deleting the file are both
        best-effort - a cleanup failure here must never mask the deployment's
        own result.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()][System.IO.FileStream]$LockStream,
        [Parameter(Mandatory)][string]$Path
    )
    if ($LockStream) {
        try { $LockStream.Close() } catch { Write-Verbose "Failed to close lock stream: $($_.Exception.Message)" }
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
    } catch { Write-Verbose "Failed to write to event log: $($_.Exception.Message)" }
}

function Get-ChromeLatestInfo {
    <#
    .SYNOPSIS
        Looks up the latest stable Chrome win64/arm64 MSI version, download URL,
        and SHA-256 via Google's versionhistory API, caching the result in
        $env:TEMP for -CacheHours.
    .DESCRIPTION
        Shared by Install-Browsers.ps1 (local install) and Push-Browsers.ps1
        (remote PsExec push) so this lookup - and the version-feed response
        shape - lives in exactly one place instead of being copy-pasted between
        them.
    #>
    param([string]$Proxy, [int]$CacheHours = 4)

    $isArm   = (Get-CimInstance Win32_Processor).Architecture -eq 12
    $archKey = if ($isArm) { 'win64-arm64' } else { 'win64' }
    $cache   = Join-Path $env:TEMP "browserdeploy-chrome-$archKey.json"
    if ((Test-Path $cache) -and (Get-Item $cache).LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
        return Get-Content $cache -Raw | ConvertFrom-Json
    }
    $api = "https://versionhistory.googleapis.com/v1/chrome/platforms/$archKey/channels/stable/versions?filter=endtime%3Dnone&num_versions=1"
    $iwArgs = @{ Uri = $api; ErrorAction = 'Stop' }
    if ($Proxy) { $iwArgs.Proxy = $Proxy }
    $json = Invoke-RestMethod @iwArgs
    $ver  = $json.versions | Select-Object -First 1
    $file = $ver.files     | Where-Object { $_.name -like '*.msi' } | Select-Object -First 1
    $fileName = if ($file.name) { $file.name } elseif ($isArm) { 'GoogleChromeStandaloneEnterpriseArm64.msi' } else { 'GoogleChromeStandaloneEnterprise64.msi' }
    $parsedVersion = try { [version]$ver.version } catch { [version]'0.0.0.0' }
    $info = [pscustomobject]@{
        Version  = $parsedVersion
        Sha256   = $file.sha256
        FileName = $fileName
        Url      = "https://dl.google.com/dl/chrome/install/$fileName"
    }
    $info | ConvertTo-Json | Set-Content $cache
    return $info
}

function Get-EdgeLatestInfo {
    <#
    .SYNOPSIS
        Looks up the latest stable Edge win MSI version, download URL, and
        SHA-256 via Microsoft's Edge Updates API, caching the result in
        $env:TEMP for -CacheHours.
    .DESCRIPTION
        Shared by Install-Browsers.ps1 and Push-Browsers.ps1 - see
        Get-ChromeLatestInfo's .DESCRIPTION. The real edgeupdates.microsoft.com
        response is a flat array of { Product, Releases: [ { Platform,
        Architecture, ProductVersion, Artifacts: [ { Location, Hash } ] } ] } -
        this repo's original Edge.ps1 (now archived) documents a real bug where
        an earlier, wrong assumption about this shape broke every run.
    #>
    param([string]$Proxy, [int]$CacheHours = 4)

    $arch  = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $cache = Join-Path $env:TEMP "browserdeploy-edge-$arch.json"
    if ((Test-Path $cache) -and (Get-Item $cache).LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
        return Get-Content $cache -Raw | ConvertFrom-Json
    }
    $iwArgs = @{ Uri = 'https://edgeupdates.microsoft.com/api/products?view=enterprise'; ErrorAction = 'Stop'; TimeoutSec = 15 }
    if ($Proxy) { $iwArgs.Proxy = $Proxy }
    $feed = Invoke-RestMethod @iwArgs
    $channelObj = $feed | Where-Object { $_.Product -eq 'Stable' }
    if (-not $channelObj) { throw "Channel 'Stable' not found in Edge Updates API response." }
    $rel = $channelObj.Releases | Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq $arch } |
        Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
    if (-not $rel) { throw "No Edge release found for Platform=Windows/Architecture=$arch." }
    $pkg = $rel.Artifacts | Where-Object { $_.Location -match '\.msi$' } | Select-Object -First 1
    if (-not $pkg) { throw 'No MSI artifact found for the latest Edge release.' }
    $info = [pscustomobject]@{
        Version  = [version]$rel.ProductVersion
        Sha256   = $pkg.Hash
        FileName = [IO.Path]::GetFileName($pkg.Location)
        Url      = $pkg.Location
    }
    $info | ConvertTo-Json | Set-Content $cache
    return $info
}

function Get-FirefoxLatestInfo {
    <#
    .SYNOPSIS
        Looks up the latest stable Firefox version and official MSI download
        URL via Mozilla's product-details API, caching the result in $env:TEMP
        for -CacheHours.
    .DESCRIPTION
        Shared by Install-Browsers.ps1 and Push-Browsers.ps1. 'firefox-msi-
        latest-ssl' is Mozilla's documented download.mozilla.org product id for
        the official win64 MSI - confirmed live during this module's own
        development (actual download + Authenticode check), it 302-redirects to
        download-installer.cdn.mozilla.net/pub/firefox/releases/<ver>/win64/en-US/Firefox Setup <ver>.msi
        and is signed 'O=Mozilla Corporation'. Unlike Chrome/Edge's feeds, no
        SHA-256 is published for it - callers must rely on the unconditional
        Authenticode check they already do for every browser, not the optional
        hash check, for this one.
    #>
    param([string]$Proxy, [int]$CacheHours = 4)

    $cache = Join-Path $env:TEMP 'browserdeploy-firefox.json'
    if ((Test-Path $cache) -and (Get-Item $cache).LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
        return Get-Content $cache -Raw | ConvertFrom-Json
    }
    $iwArgs = @{ Uri = 'https://product-details.mozilla.org/1.0/firefox_versions.json'; ErrorAction = 'Stop' }
    if ($Proxy) { $iwArgs.Proxy = $Proxy }
    $versions = Invoke-RestMethod @iwArgs
    $verStr = $versions.LATEST_FIREFOX_VERSION
    if (-not $verStr) { throw 'Could not determine latest Firefox version from product-details.mozilla.org.' }
    $parsedVersion = try { [version]$verStr } catch { [version]'0.0.0.0' }
    $info = [pscustomobject]@{
        Version  = $parsedVersion
        Sha256   = $null
        FileName = "Firefox Setup $verStr.msi"
        Url      = 'https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US'
    }
    $info | ConvertTo-Json | Set-Content $cache
    return $info
}

Export-ModuleMember -Function New-SingleInstanceLock, Close-SingleInstanceLock, Get-AdaptiveBitsPriority, Invoke-VerifiedDownload, Write-DeployLog, Get-ChromeLatestInfo, Get-EdgeLatestInfo, Get-FirefoxLatestInfo
