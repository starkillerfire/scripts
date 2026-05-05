<# Remove Universal Print printers by exact DisplayName (or share DisplayName)
   using UniversalPrintManagement. Implements:
   2) Preflight access check + reauth
   4) Unified retry wrapper with backoff + reauth (now shows Last error and avoids retry on 403/409)
   5) -Include/-Exclude and -ListOnly
   6) Progress + summary
   9) Idempotent delete logging (OK-Skipped on NotFound)
   10) -ForceSwitchAccount to prompt early
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [switch]$DryRun,
  [string]$NamesFile,
  [string[]]$Include,
  [string[]]$Exclude,
  [switch]$ListOnly,
  [switch]$ForceSwitchAccount
)

# ---- Names to remove (or pass -NamesFile) ----
$EmbeddedNames = @'
Xerox 8135.25
BOR-CPN-GCP-FIRESTATION
Xerox 8135.114
Xerox 8070.105
Xerox 7020.14
Xerox 7030.172
Xerox 7525.121
Xerox 7836.190
Xerox 7856.50
Xerox 6515
Xerox 6515.3
Xerox 6515.8
Xerox 6515.9
Xerox 6515.13
Xerox 6515.41
Xerox 6515.51
Xerox 6515.58
Xerox 6515.59
Xerox 6515.64
Xerox 6515.136
Xerox 6515.139
Xerox 6515.163
Xerox 6515.195
Xerox 6515.xx
ibr2wconn028p
IBR2WCOCN028P
IBR2WCOXX158P
IBR2WCOXX48P
IBR2WCOHP125P
IBR2WCOHP069P
IBR2WCOHP154P
IBR2WCOKY119P
IBR2WCOKY157P
IBR2WCOSTGRP
IBR2WEOCN204P
IBR2WEOC3830IP
IBR2WEOHP4250P
IBR2WHAHP27P
IBR2WHAKY26P
IBR2WRMHP032P
IBR2WRMHP057P
IBR2WRMHP056P
IBR2WRMHP56P
IBR2WRMHP150P
IBR2WRMHP151P
IBR2WRMHP153P
IBR2WRMHP157P
IBR2WRMHP164P
IBR2WRMRH043P
IBR2WRMXX45P
IBR2WRMXX46P
IBR2FOOMPCOXX3P
Q11HPT1200
Q2HPT520
Q1HPM476
Q1XEROX7835
Q3XEROX7835
q2xerox7835
HP T7100.38
HP T1100.161
TR333 Xerox 7970
TR333 Xerox 7970 GPD PS
IBR1GCPX815576P
IBR1GCPXRX217
IBR1GCPXRX138P
IBR1GCPXEROXP67
IBR1GCPXEROXP128
IBR1HHPSHARP9
IBR1HHPSHARP42
IBR1HHPSHARP152
IBR1HHPSHARP153
IBR1HHPSHARP155
'@

if ($PSVersionTable.PSEdition -ne 'Desktop') {
  Write-Warning "UniversalPrintManagement targets Windows PowerShell 5.1 (Desktop). You're running: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
}

# Build target list
if ($NamesFile -and (Test-Path -LiteralPath $NamesFile)) {
  $TargetList = Get-Content -LiteralPath $NamesFile | ForEach-Object { $_.Trim() } | Where-Object { $_ }
} else {
  $TargetList = $EmbeddedNames -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$TargetList = $TargetList | Select-Object -Unique

# Optional Include/Exclude filtering (wildcards allowed)
if ($Include) {
  $TargetList = $TargetList | Where-Object {
    $name = $_; ($Include | Where-Object { $name -like $_ }).Count -gt 0
  }
}
if ($Exclude) {
  $TargetList = $TargetList | Where-Object {
    $name = $_; ($Exclude | Where-Object { $name -like $_ }).Count -eq 0
  }
}

# ---- Logging ----
$Log = [System.Collections.Generic.List[object]]::new()
function Write-UPLog([string]$Name,[string]$Id,[string]$Action,[string]$Status,[string]$Note) {
  $Log.Add([pscustomobject]@{
    Timestamp = (Get-Date).ToString("s")
    Name      = $Name
    Id        = $Id
    Action    = $Action
    Status    = $Status
    Note      = $Note
  })
}

# ---- Module & connect ----
try {
  if (-not (Get-Module -ListAvailable -Name UniversalPrintManagement)) {
    try {
      $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
      if (-not $repo) { Register-PSRepository -Default }
      if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
      }
    } catch {}
    Install-Module -Name UniversalPrintManagement -Scope CurrentUser -Force
  }
  Import-Module UniversalPrintManagement -ErrorAction Stop
} catch {
  throw "Could not load UniversalPrintManagement: $($_.Exception.Message)"
}

# Reauth helper (used by retry wrapper & Test-UPAccess)
function Invoke-UPReauth {
  try {
    $gc = Get-Command Get-UPPrinter -ErrorAction SilentlyContinue
    if ($gc -and $gc.Parameters.ContainsKey('SwitchAccount')) {
      Write-Host "Prompting to switch account (Universal Print)…"
      $null = Get-UPPrinter -SwitchAccount -ErrorAction Stop | Select-Object -First 1
    } else {
      Write-Host "Reconnecting to Universal Print…"
      Connect-UPService -ErrorAction Stop | Out-Null
    }
  } catch {
    Write-Warning ("Reauth failed: " + $_.Exception.Message)
    throw
  }
}

# Initial connect
try {
  Connect-UPService
} catch {
  throw "Connect-UPService failed: $($_.Exception.Message)"
}

# (10) Force early switch if requested
if ($ForceSwitchAccount) {
  try { Invoke-UPReauth } catch { throw }
}

# (4) Unified retry wrapper with reauth + backoff (improved)
function Invoke-UP {
  param(
    [Parameter(Mandatory)][scriptblock]$Script,
    [int]$MaxRetries = 3
  )

  $delay = 1
  $reauthTried = $false
  $lastErr = $null
  for ($i=0; $i -lt $MaxRetries; $i++) {
    try {
      return & $Script
    } catch {
      $lastErr = $_
      $msg = $_.Exception.Message
      Write-Verbose ("Invoke-UP attempt {0}/{1} failed: {2}" -f ($i+1),$MaxRetries,$msg)

      $isAuthExpired = ($msg -match 'AADSTS|invalid_grant|token|expired|Unauthorized|401')
      $isThrottle    = ($msg -match '429|Too\s*Many\s*Requests|throttl')
      $isServerErr   = ($msg -match '\b5\d{2}\b|Internal|temporar|timeout')
      $isForbidden   = ($msg -match '\b403\b|Forbidden|insufficient|does not have permission')
      $isConflict    = ($msg -match '\b409\b|Conflict|in use|pending|active job')

      if ($isForbidden) {
        if (-not $reauthTried) { try { Invoke-UPReauth; $reauthTried = $true; continue } catch { throw } }
        throw
      }

      if ($isConflict) { throw }

      if ($isAuthExpired -and -not $reauthTried) {
        try { Invoke-UPReauth; $reauthTried = $true; continue } catch { throw }
      }

      if ($isThrottle -or $isServerErr) {
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min($delay * 2, 30)
        continue
      }

      throw
    }
  }
  $detail = if ($lastErr) { $lastErr.Exception.Message } else { "no further details" }
  throw "Operation failed after $MaxRetries retries. Last error: $detail"
}

# (2) Preflight access check
function Test-UPAccess {
  try {
    $null = Invoke-UP { Get-UPPrinter } | Select-Object -First 1
    return $true
  } catch {
    return $false
  }
}

if (-not (Test-UPAccess)) {
  throw "Account cannot access Universal Print. Ensure the proper role (e.g., Universal Print Administrator or Printer Administrator) is active (PIM) and retry."
}

# Deeper error note for CSV
function Get-DeepErrorNote {
  param($ErrorRecord)
  $txt = ($ErrorRecord.Exception.Message)
  if ($ErrorRecord.Exception.PSObject.Properties['StatusCode']) {
    $txt = "[StatusCode: {0}] {1}" -f $ErrorRecord.Exception.StatusCode, $txt
  }
  $full = ($ErrorRecord | Out-String).Trim()
  if ($full -and $full -ne $txt) { $txt = "$txt | $full" }
  if ($txt.Length -gt 1500) { $txt = $txt.Substring(0,1500) + '…' }
  return $txt
}

# Wait until shares are really gone for a printer (eventual consistency)
function Wait-UPNoShares {
  param(
    [Parameter(Mandatory)][string]$PrinterId,
    [int]$TimeoutSec = 20
  )
  $stopAt = (Get-Date).AddSeconds($TimeoutSec)
  do {
    $still = Invoke-UP { Get-UPPrinterShare } | Where-Object {
      ($_.PSObject.Properties['Printer'] -and $_.Printer.Id -eq $PrinterId) -or
      ($_.PSObject.Properties['PrinterId'] -and $_.PrinterId -eq $PrinterId)
    }
    if (-not $still) { return $true }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $stopAt)
  return $false
}

# ---- Helpers to introspect and call cmdlets safely (no pipeline) ----
function Invoke-RemoveUPPrinter {
  param([Parameter(Mandatory)][string]$PrinterId,
        [Parameter(Mandatory)][object]$PrinterObject)

  $ci = Get-Command Remove-UPPrinter -ErrorAction Stop
  $paramTried = @()
  foreach ($name in 'Id','PrinterId','UPPrinterId') {
    if ($ci.Parameters.ContainsKey($name)) {
      $paramTried += "-$name"
      $sp = @{}; $sp[$name] = $PrinterId
      Remove-UPPrinter @sp -ErrorAction Stop
      return "Removed via $($paramTried -join ' then ')"
    }
  }
  foreach ($name in 'InputObject','Printer') {
    if ($ci.Parameters.ContainsKey($name)) {
      $paramTried += "-$name(object)"
      $sp = @{}; $sp[$name] = $PrinterObject
      Remove-UPPrinter @sp -ErrorAction Stop
      return "Removed via $($paramTried -join ' then ')"
    }
  }
  throw "Remove-UPPrinter exposes no usable Id/object parameter. Params: $($(Get-Command Remove-UPPrinter).Parameters.Keys -join ', ')"
}

function Invoke-RemoveUPPrinterShare {
  param([Parameter(Mandatory)][string]$ShareId,
        [Parameter(Mandatory)][object]$ShareObject)

  $ci = Get-Command Remove-UPPrinterShare -ErrorAction Stop
  $paramTried = @()
  foreach ($name in 'Id','ShareId','PrinterShareId','UPPrinterShareId') {
    if ($ci.Parameters.ContainsKey($name)) {
      $paramTried += "-$name"
      $sp = @{}; $sp[$name] = $ShareId
      Remove-UPPrinterShare @sp -ErrorAction Stop
      return "Removed via $($paramTried -join ' then ')"
    }
  }
  foreach ($name in 'InputObject','PrinterShare','Share') {
    if ($ci.Parameters.ContainsKey($name)) {
      $paramTried += "-$name(object)"
      $sp = @{}; $sp[$name] = $ShareObject
      Remove-UPPrinterShare @sp -ErrorAction Stop
      return "Removed via $($paramTried -join ' then ')"
    }
  }
  throw "Remove-UPPrinterShare exposes no usable Id/object parameter. Params: $($(Get-Command Remove-UPPrinterShare).Parameters.Keys -join ', ')"
}

# ---- Pull all printers and shares (loop continuation tokens) ----
function Get-AllUPPrinters {
  $all=@(); $r=$null
  $r = Invoke-UP { Get-UPPrinter }
  if ($r -and $r.Results) { $all += $r.Results } elseif ($r) { $all += $r }
  while ($r -and $r.ContinuationToken) {
    $tok = $r.ContinuationToken
    $r = Invoke-UP { Get-UPPrinter -ContinuationToken $tok }
    if ($r -and $r.Results) { $all += $r.Results } elseif ($r) { $all += $r }
  }
  $all
}
function Get-AllUPPrinterShares {
  $all=@(); $r=$null
  $r = Invoke-UP { Get-UPPrinterShare }
  if ($r -and $r.Results) { $all += $r.Results } elseif ($r) { $all += $r }
  while ($r -and $r.ContinuationToken) {
    $tok = $r.ContinuationToken
    $r = Invoke-UP { Get-UPPrinterShare -ContinuationToken $tok }
    if ($r -and $r.Results) { $all += $r.Results } elseif ($r) { $all += $r }
  }
  $all
}
function Get-SharePrinterId {
  param([Parameter(Mandatory)][object]$Share)
  if ($Share.PSObject.Properties['Printer'] -and $Share.Printer -and $Share.Printer.PSObject.Properties['Id']) {
    return $Share.Printer.Id
  }
  if ($Share.PSObject.Properties['PrinterId']) { return $Share.PrinterId }
  return $null
}

$allPrinters = Get-AllUPPrinters
$allShares   = Get-AllUPPrinterShares

# Build map: printerId -> shares[]
$sharesByPrinter = @{}
foreach ($sh in $allShares) {
  $PrinterKey = Get-SharePrinterId -Share $sh
  if (-not $PrinterKey) { continue }
  if (-not $sharesByPrinter.ContainsKey($PrinterKey)) { $sharesByPrinter[$PrinterKey] = New-Object System.Collections.ArrayList }
  [void]$sharesByPrinter[$PrinterKey].Add($sh)
}

# ---- Resolve targets to printers by printer name or share name ----
$printersToDelete = New-Object System.Collections.ArrayList
$notFound = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

foreach ($t in $TargetList) {
  $found = $allPrinters | Where-Object { $_.DisplayName -ieq $t }
  if (-not $found) {
    $shareHit = $allShares | Where-Object { $_.DisplayName -ieq $t } | Select-Object -First 1
    if ($shareHit) {
      $PrinterKey = Get-SharePrinterId -Share $shareHit
      if ($PrinterKey) {
        $p = $allPrinters | Where-Object { $_.Id -eq $PrinterKey } | Select-Object -First 1
        if ($p) { $found = ,$p }
      }
    }
  }
  if ($found) { foreach($p in $found){ [void]$printersToDelete.Add($p) } }
  else { $null = $notFound.Add($t) }
}
$printersToDelete = $printersToDelete | Sort-Object Id -Unique

foreach ($nf in $notFound) { Write-UPLog $nf '' 'Lookup' 'NotFound' 'No printer or share with exact displayName' }

# (5) List-only mode to preview matches
if ($ListOnly) {
  $printersToDelete | Select-Object DisplayName,Id | Format-Table -AutoSize
  Write-Host "Matched $($printersToDelete.Count) printers. Nothing deleted due to -ListOnly."
  return
}

# ---- Unshare & delete with progress, retries, idempotency ----
$idx = 0
$tot = $printersToDelete.Count

foreach ($p in $printersToDelete) {
  $idx++
  Write-Progress -Activity "Removing Universal Print objects" -Status "$idx of $tot : $($p.DisplayName)" -PercentComplete (($idx/$tot)*100)

  $printerName = $p.DisplayName
  $printerId   = $p.Id

  # Unshare all shares for the printer, if any
  $shares = @()
  if ($sharesByPrinter.ContainsKey($printerId)) { $shares = $sharesByPrinter[$printerId] }

  foreach ($s in $shares) {
    if ($DryRun) {
      if ($PSCmdlet.ShouldProcess(("Share '{0}'" -f $s.DisplayName), "Remove-UPPrinterShare")) {
        Write-UPLog $printerName $s.Id 'Unshare' 'DryRun' ("Would remove share '{0}'" -f $s.DisplayName)
      }
      continue
    }
    try {
      if ($PSCmdlet.ShouldProcess(("Share '{0}'" -f $s.DisplayName), "Remove-UPPrinterShare")) {
        $how = Invoke-UP { Invoke-RemoveUPPrinterShare -ShareId $s.Id -ShareObject $s }
        Write-UPLog $printerName $s.Id 'Unshare' 'OK' $how
      }
    } catch {
      $note = Get-DeepErrorNote $_
      Write-UPLog $printerName $s.Id 'Unshare' 'Error' $note
    }
  }

  # After unshare, wait briefly until shares are truly gone
  if (-not $DryRun) {
    $ready = Wait-UPNoShares -PrinterId $printerId -TimeoutSec 20
    if (-not $ready) {
      Write-UPLog $printerName $printerId 'DeletePrinter' 'Error' 'Shares still present after timeout; delete skipped'
      continue
    }
  }

  # Delete the printer
  if ($DryRun) {
    if ($PSCmdlet.ShouldProcess(("Printer '{0}'" -f $printerName), "Remove-UPPrinter")) {
      Write-UPLog $printerName $printerId 'DeletePrinter' 'DryRun' ("Would remove printer '{0}'" -f $printerName)
    }
    continue
  }

  try {
    if ($PSCmdlet.ShouldProcess(("Printer '{0}'" -f $printerName), "Remove-UPPrinter")) {
      $how = Invoke-UP { Invoke-RemoveUPPrinter -PrinterId $printerId -PrinterObject $p }
      Write-UPLog $printerName $printerId 'DeletePrinter' 'OK' $how
    }
  } catch {
    $em = $_.Exception.Message
    if ($em -match 'NotFound|404') {
      Write-UPLog $printerName $printerId 'DeletePrinter' 'OK-Skipped' 'Already deleted'
    } elseif ($em -match '\b403\b|Forbidden') {
      Write-UPLog $printerName $printerId 'DeletePrinter' 'Error' 'Forbidden (need Universal Print Administrator or Printer Administrator; use -ForceSwitchAccount and/or activate PIM)'
    } elseif ($em -match '\b409\b|Conflict|in use|pending|active job') {
      Write-UPLog $printerName $printerId 'DeletePrinter' 'Error' 'Conflict: printer still in use or not fully unshared'
    } else {
      $note = Get-DeepErrorNote $_
      Write-UPLog $printerName $printerId 'DeletePrinter' 'Error' $note
    }
  }
}
Write-Progress -Activity "Removing Universal Print objects" -Completed

# (6) Summary
$okDeletes   = ($Log | Where-Object { $_.Action -eq 'DeletePrinter' -and $_.Status -like 'OK*' }).Count
$errDeletes  = ($Log | Where-Object { $_.Action -eq 'DeletePrinter' -and $_.Status -eq 'Error' }).Count
$okUnshares  = ($Log | Where-Object { $_.Action -eq 'Unshare'       -and $_.Status -eq 'OK' }).Count
$errUnshares = ($Log | Where-Object { $_.Action -eq 'Unshare'       -and $_.Status -eq 'Error' }).Count
Write-Host ("Summary: Printers OK={0}, Errors={1}; Unshares OK={2}, Errors={3}; NotFound={4}" -f $okDeletes,$errDeletes,$okUnshares,$errUnshares,$notFound.Count)

# ---- Save CSV log ----
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$path  = Join-Path $PWD ("UP-Removal-Log-{0}.csv" -f $stamp)
$Log | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Host "Log written to $path"
