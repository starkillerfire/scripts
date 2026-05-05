# Define input and output folders
$preConversionFolder = "C:\Your\Path\PreConversion"
$postConversionFolder = "C:\Your\Path\PostConversion"
$logFile = "C:\Your\Path\conversion_log.txt"

# Ensure the output folder exists
if (!(Test-Path -Path $postConversionFolder)) {
    New-Item -ItemType Directory -Path $postConversionFolder | Out-Null
}

# Create or reset the log file
New-Item -ItemType File -Path $logFile -Force | Out-Null
Add-Content -Path $logFile -Value "Conversion Log - $(Get-Date)`n------------------------------------"

$word = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false  # Keep Word hidden

    # Get all .doc and .docm files
    $files = Get-ChildItem -Path $preConversionFolder -Filter "*.doc*" | Where-Object { $_.Extension -match "^(?i)\.doc(m?)$" }

    foreach ($file in $files) {
        $docPath = [string]$file.FullName  # Ensure the path is explicitly a string
        $docExtension = $file.Extension
        $docxFileName = [string]($file.Name -replace "\.doc(m?)$", ".docx")
        $docxPath = [string](Join-Path -Path $postConversionFolder -ChildPath $docxFileName)
        $pdfPath = [string]($docxPath -replace "\.docx$", ".pdf")

        # Skip conversion if both .docx and .pdf already exist
        if ((Test-Path $docxPath) -and (Test-Path $pdfPath)) {
            Write-Host "Skipping (Already Exists): $docxPath and $pdfPath" -ForegroundColor Yellow
            Add-Content -Path $logFile -Value "SKIPPED: $docPath (Already Exists)"
            continue
        }

        Write-Host "Processing: $docPath"

        # Open the document in read-only mode
        $document = $word.Documents.Open([ref] $docPath, [ref] $false, [ref] $true)

        # Preserve metadata
        $document.Final = $false
        $document.RemovePersonalInformation = $false

        # Convert to .docx
        if (!(Test-Path $docxPath)) {  # Ensure .docx doesn't already exist
            $document.SaveAs([ref] $docxPath, [ref] 16)  # 16 = wdFormatDocumentDefault (.docx)
            Write-Host "Converted to DOCX: $docxPath" -ForegroundColor Green
            Add-Content -Path $logFile -Value "SUCCESS: Converted $docPath -> $docxPath"
        }

        # Close and reopen the new .docx to convert to PDF
        $document.Close($false)
        $document = $word.Documents.Open([ref] $docxPath, [ref] $false, [ref] $true)

        # Convert the new .docx to PDF
        if (!(Test-Path $pdfPath)) {  # Ensure PDF doesn't already exist
            $document.SaveAs([ref] $pdfPath, [ref] 17)  # 17 = wdFormatPDF
            Write-Host "Exported to PDF: $pdfPath" -ForegroundColor Cyan
            Add-Content -Path $logFile -Value "SUCCESS: Converted $docxPath -> $pdfPath"
        }

        # Close the document
        $document.Close($false)
    }
} catch {
    $errorMessage = "ERROR: $_"
    Write-Host $errorMessage -ForegroundColor Red
    Add-Content -Path $logFile -Value $errorMessage
} finally {
    # Ensure Word quits properly
    if ($word -ne $null) {
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    }
}

Write-Host "Conversion Completed! Log saved at: $logFile" -ForegroundColor Cyan
