<#
.SYNOPSIS
    Fully silent ScanSnap Home v2.22.2 installer-no GUI at any stage.
.DESCRIPTION
    1. Downloads the offline installer.
    2. Uses /extract_all to unpack it (silent).
    3. Installs VC++ 2013 & 2017 redists.
    4. Runs every ScanSnap component with its .ISS file:
         /s        - silent
         /SMS       wait + suppress pop-ups
         /f1 <iss>  feed response file (auto-accept EULA, default paths)
         /f2 <log>  per-component log
    5. Cleans up (unless -KeepFiles is passed).
    Logs aggregate installer output to %TEMP%.
#>

[CmdletBinding()]
param(
    [string]$SourceUrl  = 'https://origin.pfultd.com/downloads/ss/sshinst/w-2222/WinSSHOfflineInstaller_2_22_2.exe',
    [string]$WorkFolder = "$env:TEMP\ScanSnapHome_$([guid]::NewGuid().ToString('N'))",
    [switch]$KeepFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# origin.pfultd.com is a third-party host outside Microsoft/Google's CDNs;
# don't rely on the OS/.NET default protocol on freshly-imaged machines.
if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

# --- Paths -------------------------------------------------------------
$exePath = Join-Path $WorkFolder 'ScanSnapOffline.exe'
$logRoot = Join-Path $env:TEMP  ("ScanSnapHome-Install-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# --- Self-elevate ------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Prefer pwsh (PS7) when available, fall back to Windows PowerShell
    $elevatedExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell.exe' }
    # Rebuild from $PSBoundParameters so a non-default -SourceUrl/-KeepFiles
    # actually carries through to the elevated instance instead of silently
    # reverting to the built-in URL and always deleting the work folder.
    $argList = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [switch]) { if ($val.IsPresent) { $argList += "-$key" } }
        else { $argList += "-$key", "`"$val`"" }
    }
    $elevatedProc = Start-Process $elevatedExe -ArgumentList $argList -Verb RunAs -Wait -PassThru
    exit $elevatedProc.ExitCode
}

try {
    # 1. Download the offline bundle
    New-Item $WorkFolder -ItemType Directory -Force | Out-Null
    Invoke-WebRequest $SourceUrl -OutFile $exePath -UseBasicParsing

    # Verify the downloaded installer is validly signed by PFU/Fujitsu (the
    # ScanSnap publisher) before extracting and running anything from it -
    # $SourceUrl is a third-party origin outside Microsoft/Google's CDNs,
    # with no integrity check on this download otherwise.
    $sig = Get-AuthenticodeSignature -FilePath $exePath
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'PFU|Fujitsu') {
        throw "Downloaded installer failed Authenticode validation (status: $($sig.Status); signer: $($sig.SignerCertificate.Subject)) - refusing to run it."
    }
    Write-Host "Installer Authenticode signature verified: $($sig.SignerCertificate.Subject)" -ForegroundColor Green

    # 2. Silent extraction (no GUI, no install)
    Start-Process -FilePath $exePath `
        -ArgumentList "/extract_all=`"$WorkFolder`"","/hide_progress" `
        -WindowStyle Hidden -Wait

    $root = Join-Path $WorkFolder 'SSHomeDownloadInstaller'
    if (-not (Test-Path $root)) { throw 'Extraction failed-SSHomeDownloadInstaller not found.' }

    # 3. VC++ prerequisites
    foreach ($vc in 'ms_vcredist_x86_2013','ms_vcredist_x86_2017') {
        # Select-Object -First 1 + an explicit not-found check avoids two
        # failure modes Start-Process would otherwise hit blindly: $vcExe
        # being $null (zero matches, since .FullName on $null throws a
        # confusing parameter-binding error) or an array (multiple matches,
        # which -FilePath can't bind to a single path string).
        $vcExe = Get-ChildItem (Join-Path $root "Prerequisite\$vc") -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $vcExe) { throw "No prerequisite installer .exe found for $vc under $root\Prerequisite\$vc" }
        $vcProc = Start-Process $vcExe.FullName -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
        # 3010 = reboot required, 1638 = a newer redist is already present;
        # both are normal successful outcomes for a VC++ redist.
        if ($vcProc.ExitCode -notin @(0, 3010, 1638)) { throw "$vc exited with $($vcProc.ExitCode)" }
    }

    # 4. Main ScanSnap components (silent with .ISS)
    $download   = Join-Path $root 'download'
    $payloads   = Get-ChildItem $download -Filter *.exe

    foreach ($pkg in $payloads) {
        $issPath = Join-Path $pkg.DirectoryName ($pkg.BaseName + '.iss')
        if (-not (Test-Path $issPath)) {
            Write-Warning "No ISS file for $($pkg.Name) - skipping"
            continue
        }
        $silentArgs = @('/s','/SMS',"/f1`"$issPath`"","/f2`"$logRoot`"")
        $proc = Start-Process $pkg.FullName -ArgumentList $silentArgs -WindowStyle Hidden -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "$($pkg.Name) exited with $($proc.ExitCode)" }
    }

    Write-Host "`nScanSnap Home installed silently (EULA accepted, defaults kept)."
    $script:exitCode = 0
}
catch {
    Write-Error $_.Exception.Message
    $script:exitCode = 1
}
finally {
    if (-not $KeepFiles) { Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "Install logs: $logRoot"
}

exit $script:exitCode
