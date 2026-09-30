#Requires -Version 5.1
<#
.SYNOPSIS
    Convert .doc and .docm files to .docx and .pdf using Word COM interop.

.PARAMETER InputFolder
    Folder containing the source .doc / .docm files.

.PARAMETER OutputFolder
    Destination folder for converted .docx and .pdf files. Created if absent.

.PARAMETER LogFile
    Path to the conversion log. Defaults to conversion_log.txt inside OutputFolder.

.EXAMPLE
    .\Doc conversion.ps1 -InputFolder C:\Docs\Legacy -OutputFolder C:\Docs\Converted

.EXAMPLE
    .\Doc conversion.ps1 -InputFolder C:\Docs\Legacy -OutputFolder C:\Docs\Converted -LogFile C:\Logs\doc_convert.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $InputFolder,
    [Parameter(Mandatory)] [string] $OutputFolder,
    [string] $LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Word SaveAs format constants
$wdFormatDocumentDefault = 16   # .docx
$wdFormatPDF             = 17   # .pdf

if (-not (Test-Path $InputFolder))  { throw "Input folder not found: $InputFolder" }
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
if (-not $LogFile) { $LogFile = Join-Path $OutputFolder 'conversion_log.txt' }

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

Add-Content -Path $LogFile -Value ("Conversion Log - {0}`n{1}" -f (Get-Date), ('-' * 40)) -Encoding UTF8

# @() wrapper: under Set-StrictMode, a single match yields a bare scalar with
# no .Count property, and the check below would throw instead of reading 1.
$files = @(Get-ChildItem -Path $InputFolder -Filter '*.doc*' |
         Where-Object { $_.Extension -match '^(?i)\.doc(m?)$' })

if ($files.Count -eq 0) {
    Write-Log "No .doc/.docm files found in $InputFolder."
    return
}

# If both a .doc and .docm exist with the same base name (e.g. "report.doc"
# and "report.docm"), they'd otherwise both map to the identical output
# filename ("report.docx"/"report.pdf") - whichever is processed second
# would see both outputs already present and get silently logged as
# "SKIPPED (already exists)", discarding that file's conversion while
# making it look handled. Only files with a colliding base name get the
# extension folded into their output name; everything else keeps the clean
# "name.docx" naming.
$duplicateBaseNames = $files | Group-Object BaseName | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name

Write-Log "Found $($files.Count) file(s). Starting conversion..."
$errored = 0

$word = $null
try {
    try {
        $word = New-Object -ComObject Word.Application
    } catch {
        Write-Log "ERROR: Could not start Word - is Microsoft Word installed/licensed on this machine? $($_.Exception.Message)"
        throw
    }
    $word.Visible = $false
    # Without this, a modal Word prompt (format-compatibility warning on
    # .docm->.docx, "convert file" prompt on legacy .doc, etc.) pops up
    # invisibly (since Visible = $false) and blocks forever with no session
    # to dismiss it - hanging the whole batch with no timeout.
    $word.DisplayAlerts = 0   # wdAlertsNone
    # Force-disable macros (including AutoOpen) on every document this opens,
    # regardless of whatever Trust Center policy happens to be set on the
    # machine running this - these are untrusted legacy .doc/.docm files
    # being fed to Documents.Open programmatically below.
    $word.AutomationSecurity = 3   # msoAutomationSecurityForceDisable

    foreach ($file in $files) {
        $outBaseName = if ($duplicateBaseNames -contains $file.BaseName) { "$($file.BaseName)$($file.Extension)" } else { $file.BaseName }
        $docxPath = Join-Path $OutputFolder ($outBaseName + '.docx')
        $pdfPath  = Join-Path $OutputFolder ($outBaseName + '.pdf')

        if ((Test-Path $docxPath) -and (Test-Path $pdfPath)) {
            Write-Log "SKIPPED (already exists): $($file.Name)"
            continue
        }

        Write-Log "Processing: $($file.Name)"
        if ($file.Extension -match '(?i)\.docm$') {
            Write-Log "  NOTE: $($file.Name) is macro-enabled (.docm) - VBA macros are NOT preserved in the converted .docx (a macro-free format)."
        }
        $document = $null
        try {
            $document = $word.Documents.Open(
                [ref][string]$file.FullName, [ref]$false, [ref]$true)

            $document.Final = $false
            $document.RemovePersonalInformation = $false

            if (-not (Test-Path $docxPath)) {
                $document.SaveAs([ref]$docxPath, [ref]$wdFormatDocumentDefault)
                Write-Log "  DOCX: $docxPath"
            }

            $document.Close($false)
            $document = $null

            # Reopen the .docx to export as PDF
            $document = $word.Documents.Open([ref]$docxPath, [ref]$false, [ref]$true)
            if (-not (Test-Path $pdfPath)) {
                $document.SaveAs([ref]$pdfPath, [ref]$wdFormatPDF)
                Write-Log "  PDF:  $pdfPath"
            }
        } catch {
            Write-Log "  ERROR: $($file.Name) - $($_.Exception.Message)"
            $errored++
        } finally {
            if ($null -ne $document) {
                try { $document.Close($false) } catch {}
                $document = $null
            }
        }
    }
} finally {
    if ($null -ne $word) {
        $wordPid = $null
        try { $wordPid = $word.Application.PID } catch {}
        try {
            $word.Quit()
        } catch {
            Write-Log "WARNING: Word.Quit() failed; attempting to kill the process directly. $($_.Exception.Message)"
            if ($wordPid) {
                try { Stop-Process -Id $wordPid -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
        try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null } catch {}
        $word = $null
    }
}

Write-Log "Conversion complete ($errored error(s)). Log saved to: $LogFile"
exit ($(if ($errored -gt 0) { 1 } else { 0 }))
