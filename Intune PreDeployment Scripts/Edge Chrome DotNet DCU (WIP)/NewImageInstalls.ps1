param(
    [string]$Architecture = "x64",
    [string]$Platform = "Windows",
    [string]$Channel = "Stable"
)

function InstallChrome {
	Write-Output ""
	Write-Output "Installing Google Chrome..."
try {
	$uri = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
	$path = "$PSScriptRoot\googlechromestandaloneenterprise64.msi" 
	$wc = New-Object net.webclient
	$wc.Downloadfile($uri, $path)	
	Start-Process msiexec -ArgumentList "/i `"$path`"" -Wait;
	Remove-Item -Path $path -Force
 } catch {
	 Write-Output ""
	 Write-Output "Error downloading Chrome..."
	return $null
	}
}

function InstallEdge {
Write-Output ""
Write-Output "Installing Microsoft Edge..."

$apiUrl = "https://edgeupdates.microsoft.com/api/products?view=enterprise"

try {
    $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
}
catch {
    Write-Error "Failed to retrieve JSON from API: $_"
    exit 1
	
}

$channelObj = $response | Where-Object { $_.Product -eq $Channel }
if (-not $channelObj) {
    Write-Error "Channel '$Channel' not found in API response."
    exit 1

}

# Filter matching releases by platform & architecture
$filtered = $channelObj.Releases |
    Where-Object {
        $_.Platform -eq $Platform -and $_.Architecture -eq $Architecture
    }

if (-not $filtered) {
    Write-Error "No releases found for $Platform / $Architecture."
    exit 1

}

# Sort versions and pick latest
$latestRelease = $filtered |
    Sort-Object {[version]$_.ProductVersion} -Descending |
    Select-Object -First 1

if (-not $latestRelease) {
    Write-Error "Could not identify the latest release."
    exit 1
}

# Among artifacts, prefer MSI installers
$artifact = $latestRelease.Artifacts |
    Where-Object { $_.Location -match "\.msi$" } |
    Select-Object -First 1

if (-not $artifact) {
    Write-Error "MSI artifact not found for latest release."
    exit 1
}

try{
	$path = "$PSScriptRoot\MicrosoftEdgeEnterpriseX64.msi"
	$wc = New-Object net.webclient
	$wc.Downloadfile($artifact.Location, $path)
	Start-Process msiexec -ArgumentList "/i `"$path`"" -Wait;
	Remove-Item -Path $path -Force
} catch {
		Write-Output "Error Downloading Edge..."
	}
}




function InstalldotNet {
	Write-Output ""
	Write-Output "Installing .Net Desktop Runtime 8.0.x..."
	try {
		winget install Microsoft.DotNet.DesktopRuntime.8 -e --accept-package-agreements --accept-source-agreements 
		if ($LASTEXITCODE -ne 0) {
        throw "winget command failed with exit code: $LASTEXITCODE" }
    
	} catch {
			try {
				$uri = "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/8.0.18/windowsdesktop-runtime-8.0.18-win-x64.exe"
				$path = "$PSScriptRoot\windowsdesktop-runtime-8.0.18-win-x64.exe"
				$wc = New-Object net.webclient
				$wc.Downloadfile($uri, $path)
				Start-Process -Wait -FilePath "$path"
				Remove-Item -Path $path -Force
			} catch {
				Write-Output ""
				Write-Output "Error downloading .Net Desktop Runtime..."
				return $null
		}
	}
}

function InstallDCU {
	Write-Output "Installing Dell Command Update..."
	try { 
		winget install Dell.CommandUpdate -e --accept-package-agreements --accept-source-agreements 
		
		if ($LASTEXITCODE -ne 0) {
        throw "winget command failed with exit code: $LASTEXITCODE" } 
		} catch {
	try {
	
	$uri = "https://dl.dell.com/FOLDER13309588M/1/Dell-Command-Update-Windows-Universal-Application_C8JXV_WIN64_5.5.0_A00.EXE"
	$path = "$PSScriptRoot\Dell-Command-Update-Windows-Universal-Application_C8JXV_WIN64_5.5.0_A00.EXE"
	$wc = New-Object net.webclient
	$wc.Downloadfile($uri, $path)
	Start-Process -Wait -FilePath "$path"
	Remove-Item -Path $path -Force
	} catch {
		Write-Output ""
		Write-Output "Error downloading Dell Command Update..."
		return $null
		}
	}
}

		

########################

#Edge
try {
	InstallEdge
} catch { 
	Write-Error "Error installing Edge..."
	}



#Chrome
try {
		InstallChrome
	} catch { 
	Write-Error "Error installing Chrome..." 
}
		

#dotnet
try {
	InstalldotNet
} catch { 
	Write-Error "Error installing .Net Desktop Runtime..." 
	}

#DUC
#WIP: Getting Access Denied error when trying to download from the URL.
#Installation works fine through Winget, but winget doesn't work in the OOBE.

try {
	InstallDCU
} catch {
	Write-Error "Error installing Dell Command Update..."
}



