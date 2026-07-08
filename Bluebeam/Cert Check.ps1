<# 
.SYNOPSIS
  Test TSA chain(s) and collect CAPI2 revocation logs into one ZIP (PowerShell 5.1).

.DESCRIPTION
  - Requires Administrator. Exits immediately if not elevated.
  - Scans CurrentUser & LocalMachine Intermediate CA stores for certificates with EKU = Time Stamping (1.3.6.1.5.5.7.3.8).
  - For each candidate, runs 'certutil -verify -urlfetch' (live revocation) and saves output.
  - Enables CAPI2 Operational logging, lets you reproduce, exports recent Event ID 11 entries.
  - (Intentionally does NOT disable CAPI2; logging stays ON so you can keep testing.)
  - Captures a minimal environment snapshot.
  - Produces a ZIP on the Desktop with all results.

.PARAMETERS
  -MinutesToCapture     Minutes of CAPI2 events to export (default 20)
  -MaxEvents            Maximum CAPI2 events to export (default 200)
  -NoPause              Skip the "reproduce now" pause (non-interactive)
  -DisableLoggingOnExit Turn CAPI2 Operational logging back off before the
                        script exits, instead of leaving it on for further
                        manual testing (the default). Use this for
                        unattended/scripted runs where nobody will remember
                        to run Disable CAI2.ps1 afterward.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter()][ValidateRange(1,240)][int]$MinutesToCapture = 20,
  [Parameter()][ValidateRange(10,2000)][int]$MaxEvents = 200,
  [Parameter()][switch]$NoPause,
  [Parameter()][switch]$DisableLoggingOnExit
)

# --- Require Administrator ---------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERR] This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and choose 'Run as administrator'."
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Ok   { param([string]$Message) Write-Host "[ OK ] $Message" -ForegroundColor Green }
function Write-Note { param([string]$Message) Write-Host "[ .. ] $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Warning $Message }
function Write-Err  { param([string]$Message) Write-Host "[ERR] $Message" -ForegroundColor Red }

# --- Setup output folders ----------------------------------------------------
$stamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$desktop  = [Environment]::GetFolderPath('Desktop')
$outRoot  = Join-Path $desktop "TSA_CAPI2_Results_$stamp"
$tsaDir   = Join-Path $outRoot "TSA_Verify"
$capiDir  = Join-Path $outRoot "CAPI2"
$envDir   = Join-Path $outRoot "Env"
$zipPath  = Join-Path $desktop "TSA_CAPI2_Results_$stamp.zip"

New-Item -ItemType Directory -Force -Path $outRoot,$tsaDir,$capiDir,$envDir | Out-Null

# --- Helper: run console tool and capture output ----------------------------
function Invoke-ConsoleTool {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory)][string]$FileName,
    [Parameter()][string]$Arguments = "",
    [Parameter(Mandatory)][string]$OutPath
  )
  if ($PSCmdlet.ShouldProcess("$FileName $Arguments","Run and save output to $OutPath")) {
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $p.StartInfo.FileName = $FileName
    $p.StartInfo.Arguments = $Arguments
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError  = $true
    $p.StartInfo.UseShellExecute        = $false
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $stdout | Set-Content -LiteralPath $OutPath -Encoding UTF8
    if ($stderr) { Add-Content -LiteralPath $OutPath -Encoding UTF8 "`n--- STDERR ---`n$stderr" }
  }
}

# --- 1) TSA chain scan + live verification ----------------------------------
Write-Note "Scanning Intermediate CA stores for Time Stamping EKU (1.3.6.1.5.5.7.3.8)..."

$ekuTS = '1.3.6.1.5.5.7.3.8'
$stores = @('Cert:\CurrentUser\CA','Cert:\LocalMachine\CA')

$tsaCandidates = New-Object System.Collections.ArrayList

foreach ($store in $stores) {
  if (-not (Test-Path $store)) { continue }
  try {
    $items = Get-ChildItem -Path $store -ErrorAction Stop
    foreach ($c in $items) {
      $ekuExts = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
      if ($ekuExts) {
        $ekus = foreach ($ex in $ekuExts) { foreach ($oid in $ex.EnhancedKeyUsages) { $oid.Value } }
        if ($ekus -contains $ekuTS) {
          [void]$tsaCandidates.Add([pscustomobject]@{
            Subject    = $c.Subject
            Issuer     = $c.Issuer
            Thumbprint = $c.Thumbprint
            NotAfter   = $c.NotAfter
            Store      = $store
          })
        }
      }
    }
  } catch {
    Write-Warn "Could not read ${store}: $($_.Exception.Message)"
  }
}

$summaryCsv = Join-Path $tsaDir "TSA_Candidates.csv"
$tsaCandidates | Sort-Object NotAfter -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv
Write-Ok "Found $($tsaCandidates.Count) TSA candidate(s). Summary: $summaryCsv"

# Verify each TSA candidate with live revocation
foreach ($row in $tsaCandidates) {
  try {
    $tp = $row.Thumbprint
    $cert = Get-ChildItem Cert:\CurrentUser\CA,Cert:\LocalMachine\CA -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -ieq $tp } | Select-Object -First 1
    if ($null -eq $cert) { continue }
    $tmpCer = Join-Path $env:TEMP "$tp.cer"
    Export-Certificate -Cert $cert -FilePath $tmpCer | Out-Null
    $outFile = Join-Path $tsaDir ("Verify_{0}.txt" -f $tp)
    Invoke-ConsoleTool -FileName "certutil.exe" -Arguments "-verify -urlfetch `"$tmpCer`"" -OutPath $outFile
    if (Test-Path $tmpCer) { Remove-Item -LiteralPath $tmpCer -Force }
  } catch {
    Write-Warn "Verification failed for $($row.Subject) [$($row.Thumbprint)]: $($_.Exception.Message)"
  }
}
Write-Ok "TSA verification outputs saved under: $tsaDir"

# --- 2) CAPI2 enable → (optional pause) → export recent Event 11 ------------
$capiChannel = "Microsoft-Windows-CAPI2/Operational"
try {
  wevtutil sl "$capiChannel" /e:true | Out-Null
  Write-Ok "CAPI2 Operational logging is ENABLED and will remain on after this script finishes."
} catch {
  Write-Err "Could not enable CAPI2 logging: $($_.Exception.Message)"
  Write-Host "Exiting." -ForegroundColor Red
  exit 1
}

if (-not $NoPause) {
  Write-Host ""
  Write-Host ">>> Reproduce the PDF signing issue in Bluebeam NOW. When finished, press ENTER to export logs (logging will stay on)." -ForegroundColor Yellow
  Read-Host | Out-Null
}

# Export recent Event ID 11 entries
try {
  $since = (Get-Date).AddMinutes(-$MinutesToCapture).ToString("o")
  # position() <= $MaxEvents actually applies the -MaxEvents limit - this
  # parameter used to be declared/validated/documented but never referenced
  # anywhere in the actual wevtutil query, so passing -MaxEvents had no
  # effect at all.
  $query = @"
<QueryList>
  <Query Id="0" Path="$capiChannel">
    <Select>*[System[(EventID=11) and TimeCreated[@SystemTime >= '$since']]][position() &lt;= $MaxEvents]</Select>
  </Query>
</QueryList>
"@
  $evtx = Join-Path $capiDir "CAPI2_Event11_Recent.evtx"
  wevtutil epl "$capiChannel" "$evtx" /q:"$query" | Out-Null
  Write-Ok "Exported recent Event ID 11 entries → $evtx"
} catch {
  Write-Warn "CAPI2 export failed: $($_.Exception.Message)"
}

# --- 3) Minimal environment snapshot ----------------------------------------
try {
  $envTxt = Join-Path $envDir "Environment.txt"
  $os = Get-CimInstance Win32_OperatingSystem
  $bb = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Bluebeam Revu' }
@"
Machine : $env:COMPUTERNAME
User    : $env:USERNAME
OS      : $($os.Caption) ($($os.Version)) Build $([Environment]::OSVersion.Version.Build)

Bluebeam installs:
$($bb | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher -Auto | Out-String)
"@ | Set-Content -LiteralPath $envTxt -Encoding UTF8
  Write-Ok "Captured environment snapshot."
} catch {
  Write-Warn "Environment capture failed: $($_.Exception.Message)"
}

# --- 4) ZIP everything -------------------------------------------------------
try {
  if (Test-Path -LiteralPath $zipPath) {
    if ($PSCmdlet.ShouldProcess($zipPath,"Remove existing ZIP")) {
      Remove-Item -LiteralPath $zipPath -Force
    }
  }
  Compress-Archive -Path (Join-Path $outRoot '*') -DestinationPath $zipPath -Force
  Write-Ok "Bundle created: $zipPath"
} catch {
  Write-Err "Failed to create ZIP: $($_.Exception.Message)"
}

if ($DisableLoggingOnExit) {
  try {
    wevtutil sl "$capiChannel" /e:false | Out-Null
    Write-Ok "CAPI2 Operational logging has been DISABLED (per -DisableLoggingOnExit)."
  } catch {
    Write-Err "Failed to disable CAPI2 logging: $($_.Exception.Message)"
    Write-Host "  Disable it manually with: wevtutil sl `"$capiChannel`" /e:false" -ForegroundColor Yellow
  }
} else {
  Write-Host "`nCAPI2 logging is STILL ENABLED."
  Write-Host "When you're done testing, disable it with this command (or run Disable CAI2.ps1):" -ForegroundColor Yellow
  Write-Host "  wevtutil sl `"Microsoft-Windows-CAPI2/Operational`" /e:false" -ForegroundColor Yellow
}
Write-Host "`nDone. Share the ZIP with your PKI/Bluebeam support team."
