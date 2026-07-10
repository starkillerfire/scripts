<# 
Bluebeam Revu 21 Log Collector
- Collects Revu logs
- Enables CAPI2 logging, prompts you to reproduce, exports CAPI2 events, then disables
- Captures cert/chain/CRL diagnostics (certutil)
- Zips everything into one file on your Desktop

References:
- Bluebeam logs & "Explore Log Folder" / Extended Debugging
- Microsoft CAPI2 Operational logging
- certutil -URLcache and -getreg chain
#>

[CmdletBinding()]
param(
  [int]$MinutesToCapture = 20,   # CAPI2 events timeframe
  [switch]$ClearUrlCache         # Opt-in: clear the user's CRL/URL cache after recording it
)

$ErrorActionPreference = "Stop"

function Write-Info($m){ Write-Host "[INFO] $m" }
function Write-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }

# Prep working folder
$Stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$OutRoot = Join-Path $env:USERPROFILE ("Desktop\\Bluebeam_SupportBundle_$Stamp")
$LogsDir = Join-Path $OutRoot "BluebeamLogs"
$DiagDir = Join-Path $OutRoot "Diagnostics"
$EvtDir  = Join-Path $OutRoot "CAPI2"
New-Item -ItemType Directory -Force -Path $OutRoot,$LogsDir,$DiagDir,$EvtDir | Out-Null

# 1) Bluebeam Revu 21 logs
$RevuLogs = Join-Path $env:LOCALAPPDATA "Bluebeam\Revu\21\Logs"
if (Test-Path $RevuLogs) {
  Copy-Item -Path (Join-Path $RevuLogs "*") -Destination $LogsDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Ok "Copied Bluebeam Revu logs from: $RevuLogs"
} else {
  Write-Warn "Revu 21 log folder not found at $RevuLogs (open Revu → Preferences → Admin → Explore Log Folder to verify)."
}

# Add a README with quick context
$readme = @"
Bluebeam Revu 21 log bundle
Generated: $(Get-Date -Format u)

If Support wants more detail:
- In Revu: Revu → Preferences (Ctrl+K) → Admin → ENABLE 'Extended Debugging', then reproduce the issue and re-run this script. (Revu may need a restart.)

"@
$readme | Set-Content (Join-Path $OutRoot "README.txt")

# 2) Environment snapshot
$EnvTxt = Join-Path $DiagDir "env.txt"
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$bbApps = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
  ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
  Where-Object { $_.DisplayName -match "Bluebeam Revu" }

@"
MachineName: $env:COMPUTERNAME
User:        $env:USERNAME
OS:          $($os.Caption) ($($os.Version)) Build $([Environment]::OSVersion.Version.Build)
Installed Bluebeam entries:
$($bbApps | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher -Auto | Out-String)
"@ | Set-Content $EnvTxt

# 3) CAPI2 logging (PKI chain & revocation trace)
$capilog = "Microsoft-Windows-CAPI2/Operational"
$capiEnabled = $false
try {
  wevtutil sl "$capilog" /e:true | Out-Null
  $capiEnabled = $true
  Write-Ok "Enabled CAPI2 Operational logging."
} catch { Warn "Could not enable CAPI2 logging (try running PowerShell as Administrator). Continuing." }

try {
  Write-Host ""
  Write-Host ">>> Now reproduce the Bluebeam signing failure. When you're done, press ENTER to continue."
  Read-Host | Out-Null

  # Export recent CAPI2 events
  try {
    $Since = (Get-Date).AddMinutes(-[int]$MinutesToCapture).ToString("o")
    $Query = @"
<QueryList>
  <Query Id="0" Path="$capilog">
    <Select>*[System[TimeCreated[@SystemTime >= '$Since']]]</Select>
  </Query>
</QueryList>
"@
    $evtx = Join-Path $EvtDir "CAPI2_Recent.evtx"
    wevtutil epl "$capilog" "$evtx" /q:"$Query" | Out-Null
    Write-Ok "Exported recent CAPI2 events → $evtx"
  } catch { Warn "CAPI2 export failed (insufficient rights or no events). You can export manually from Event Viewer." }
} finally {
  # This is the only place CAPI2 logging gets turned back off, so it needs
  # to run even if the "reproduce the issue" prompt or the event export
  # above throws unexpectedly - otherwise a single hiccup mid-script would
  # leave verbose CAPI2 logging running indefinitely on the user's machine.
  if ($capiEnabled) {
    try { wevtutil sl "$capilog" /e:false | Out-Null } catch {}
  }
}

# 4) Cert & revocation diagnostics
function Invoke-CmdOut($file, $cmd, $Arguments) {
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName = $cmd
  $p.StartInfo.Arguments = $Arguments
  $p.StartInfo.RedirectStandardOutput = $true
  $p.StartInfo.RedirectStandardError  = $true
  $p.StartInfo.UseShellExecute = $false
  $null = $p.Start()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  $out | Set-Content $file
  if ($err) { Add-Content $file "`n--- STDERR ---`n$err" }
}

# a) Current user's personal & intermediate stores
# Wrapped like the LocalMachine/gpresult blocks below: with
# $ErrorActionPreference = 'Stop' set globally, an unwrapped certutil
# failure here (missing/blocked certutil.exe, etc.) would abort the whole
# script before the ZIP ever gets produced - a single hiccup shouldn't cost
# the technician the entire support bundle.
try {
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_user_my.txt")  "certutil.exe" "-user -store my"
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_user_ca.txt")  "certutil.exe" "-user -store ca"
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_user_root.txt") "certutil.exe" "-user -store root"
} catch { Warn "Could not read current-user certificate stores: $($_.Exception.Message)" }

# b) LocalMachine stores (if admin)
try {
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_lm_my.txt")   "certutil.exe" "-store my"
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_lm_ca.txt")   "certutil.exe" "-store ca"
  Invoke-CmdOut (Join-Path $DiagDir "cert_store_lm_root.txt") "certutil.exe" "-store root"
} catch { Warn "Could not read LocalMachine stores (need elevation). Skipping." }

# c) Chain engine config & URL cache
try {
  Invoke-CmdOut (Join-Path $DiagDir "cert_chain_config.txt") "certutil.exe" "-getreg chain"
  Invoke-CmdOut (Join-Path $DiagDir "cert_urlcache_list.txt") "certutil.exe" "-URLcache *"
} catch { Warn "Could not read chain config / URL cache: $($_.Exception.Message)" }

# (Optional) clear user CRL/URL cache AFTER we recorded it - opt-in via -ClearUrlCache
if ($ClearUrlCache) {
  try {
    Invoke-CmdOut (Join-Path $DiagDir "cert_urlcache_clear.txt") "certutil.exe" "-URLcache * delete"
  } catch { Warn "Could not clear URL cache (non-fatal)." }
} else {
  Write-Info "Skipping URL cache clear (pass -ClearUrlCache to force fresh revocation checks)."
}

# 5) GPResult (to show no custom PKI policy)
try {
  $rsop = Join-Path $DiagDir "gpresult.html"
  gpresult /h "$rsop" | Out-Null
  Write-Ok "Captured RSOP → $rsop"
} catch { Warn "gpresult failed (non-fatal)." }

# 6) Zip it all up
$ZipPath = Join-Path $env:USERPROFILE ("Desktop\\Bluebeam_SupportBundle_$Stamp.zip")
try {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($OutRoot, $ZipPath)
  Write-Ok "Bundle created: $ZipPath"
} catch {
  Write-Warn "Could not create the ZIP bundle: $($_.Exception.Message). The collected files are still available, unzipped, at: $OutRoot"
}
Write-Host ""
Write-Host "Attach this ZIP to your Bluebeam Support case."
Write-Host "If Support wants more detail, enable 'Extended Debugging' in Revu (Preferences → Admin), reproduce, and run again."
