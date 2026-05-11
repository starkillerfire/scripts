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

$files = Get-ChildItem -Path $InputFolder -Filter '*.doc*' |
         Where-Object { $_.Extension -match '^(?i)\.doc(m?)$' }

if ($files.Count -eq 0) {
    Write-Log "No .doc/.docm files found in $InputFolder."
    return
}

Write-Log "Found $($files.Count) file(s). Starting conversion..."

$word = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false

    foreach ($file in $files) {
        $docxPath = Join-Path $OutputFolder ($file.BaseName + '.docx')
        $pdfPath  = Join-Path $OutputFolder ($file.BaseName + '.pdf')

        if ((Test-Path $docxPath) -and (Test-Path $pdfPath)) {
            Write-Log "SKIPPED (already exists): $($file.Name)"
            continue
        }

        Write-Log "Processing: $($file.Name)"
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
        } finally {
            if ($null -ne $document) {
                try { $document.Close($false) } catch {}
                $document = $null
            }
        }
    }
} finally {
    if ($null -ne $word) {
        try { $word.Quit() } catch {}
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
        $word = $null
    }
}

Write-Log "Conversion complete. Log saved to: $LogFile"
