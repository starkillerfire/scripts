#Requires -Version 5.1
<#
.SYNOPSIS
    Convert HEIC images to JPEG using WPF BitmapDecoder/Encoder.

.DESCRIPTION
    Requires "HEIF Image Extensions" from the Microsoft Store.
    The script will attempt a silent winget install if the extension is missing.

.PARAMETER SourceFolder
    Folder containing .heic files to convert.

.PARAMETER OutputFolder
    Destination folder for .jpg files. Created if it does not exist.
    Defaults to a "JPEG" subfolder inside SourceFolder.

.PARAMETER Quality
    JPEG quality level (1-100). Default: 95.

.PARAMETER Recurse
    Search SourceFolder recursively for .heic files.

.PARAMETER LogFile
    Path to a plaintext log of the conversion run. Defaults to
    conversion_log.txt inside OutputFolder.

.EXAMPLE
    .\HEIC-to-JPEG.ps1 -SourceFolder C:\Photos\HEIC -OutputFolder C:\Photos\JPEG

.EXAMPLE
    .\HEIC-to-JPEG.ps1 -SourceFolder C:\Photos -Recurse -Quality 85
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SourceFolder,

    [string] $OutputFolder,

    [ValidateRange(1, 100)]
    [int]    $Quality = 95,

    [switch] $Recurse,

    [string] $LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Validate source ---
if (-not (Test-Path $SourceFolder)) { throw "Source folder not found: $SourceFolder" }

# --- Default output folder ---
if (-not $OutputFolder) { $OutputFolder = Join-Path $SourceFolder 'JPEG' }
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
if (-not $LogFile) { $LogFile = Join-Path $OutputFolder 'conversion_log.txt' }

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

# --- Ensure HEIF extension is present ---
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

if (-not (Get-AppxPackage -Name Microsoft.HEIFImageExtension -ErrorAction SilentlyContinue)) {
    Write-Log "HEIF Image Extensions not found - attempting winget install..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget not available. Install HEIF Image Extensions manually from the Microsoft Store (search 'HEIF Image Extensions')."
    }
    winget install --id 9PMMSR1CGPWG --source msstore --accept-package-agreements --accept-source-agreements --silent
    if (-not (Get-AppxPackage -Name Microsoft.HEIFImageExtension -ErrorAction SilentlyContinue)) {
        throw "HEIF extension install failed. Install it manually from the Microsoft Store."
    }
    Write-Log "HEIF Image Extensions installed."
}

# --- Discover files ---
$getChildArgs = @{ Path = $SourceFolder; Filter = '*.heic' }
if ($Recurse) { $getChildArgs['Recurse'] = $true }
# @() wrapper: under Set-StrictMode, a single match yields a bare scalar with
# no .Count property, and the check below would throw instead of reading 1.
$files = @(Get-ChildItem @getChildArgs)

if ($files.Count -eq 0) {
    Write-Log "No .heic files found in $SourceFolder"
    exit 0
}

Write-Log "Converting $($files.Count) file(s) at quality $Quality..."

$converted = 0
$skipped   = 0
$errored   = 0

foreach ($file in $files) {
    $jpgPath = Join-Path $OutputFolder ($file.BaseName + '.jpg')

    if (Test-Path $jpgPath) {
        Write-Verbose "Skipping (already exists): $($file.Name)"
        $skipped++
        continue
    }

    try {
        $uri     = [System.Uri]::new($file.FullName)
        $decoder = [System.Windows.Media.Imaging.BitmapDecoder]::Create(
            $uri,
            [System.Windows.Media.Imaging.BitmapCreateOptions]::None,
            [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        )

        $encoder              = New-Object System.Windows.Media.Imaging.JpegBitmapEncoder
        $encoder.QualityLevel = $Quality
        $encoder.Frames.Add($decoder.Frames[0])

        $stream = [System.IO.File]::Open($jpgPath, [System.IO.FileMode]::Create)
        try   { $encoder.Save($stream) }
        finally { $stream.Dispose() }

        Write-Log "Converted: $($file.Name)"
        $converted++
    } catch {
        Write-Log "Failed: $($file.Name) - $_"
        $errored++
    }
}

Write-Host ""
Write-Log "Done - $converted converted, $skipped skipped, $errored errors."
exit ($(if ($errored -gt 0) { 1 } else { 0 }))
