Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
    .SYNOPSIS
    Returns the profile path of the interactively logged-on user, if any.

    .DESCRIPTION
    Returns $null when the console session has no interactive user (e.g. a
    script pushed by Intune and running as SYSTEM) rather than falling back
    to the calling process's own profile, so callers can tell the difference
    between "no one is logged on" and "this is the logged-on user's path."

    .OUTPUTS
    System.String or $null.
#>
function Get-LoggedOnUserProfile {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $loggedOnUser = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue

    if (-not $loggedOnUser) {
        return $null
    }

    $userName = $loggedOnUser.Split('\')[-1]

    $profilePath = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -match "\\$([regex]::Escape($userName))$" } |
        Select-Object -First 1 -ExpandProperty LocalPath -ErrorAction SilentlyContinue

    return $profilePath
}

<#
    .SYNOPSIS
    Checks whether the current process is running as SYSTEM.

    .OUTPUTS
    System.Boolean.
#>
function Test-RunningAsSystem {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

<#
    .SYNOPSIS
    Resolves (and creates) the folder a diagnostic script should write its output to.

    .DESCRIPTION
    Picks the output folder in this order:
      1. -RequestedPath, if given.
      2. The interactively logged-on user's Downloads folder, if one exists
         and the process isn't running as SYSTEM. (Under SYSTEM - the common
         case for an Intune-pushed run - there usually isn't a usable
         interactive Downloads folder, and writing there under
         $env:USERPROFILE would land in the SYSTEM profile, not somewhere a
         technician will ever look.)
      3. C:\ProgramData\IntuneDiagnostics\<FolderName> - a fixed, predictable
         location that works the same whether the script is run manually or
         pushed as SYSTEM.
      4. C:\<FolderName> as a last resort if even ProgramData can't be
         written to.

    .PARAMETER FolderName
    Name of the diagnostic run's own subfolder (e.g. a script name + timestamp).

    .PARAMETER RequestedPath
    Explicit output folder to use instead of the automatic resolution above.

    .OUTPUTS
    System.String - the created output folder's full path.
#>
function Resolve-DiagnosticOutputPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderName,

        [string]$RequestedPath
    )

    $candidate = $null

    if ($RequestedPath) {
        $candidate = Join-Path $RequestedPath $FolderName
    }
    elseif (-not (Test-RunningAsSystem)) {
        $userProfile = Get-LoggedOnUserProfile
        if ($userProfile) {
            $candidate = Join-Path (Join-Path $userProfile 'Downloads') $FolderName
        }
    }

    if (-not $candidate) {
        $candidate = Join-Path 'C:\ProgramData\IntuneDiagnostics' $FolderName
    }

    try {
        New-Item -Path $candidate -ItemType Directory -Force -ErrorAction Stop | Out-Null
        return $candidate
    }
    catch {
        Write-Warning "Could not create '$candidate' ($($_.Exception.Message)) - falling back to C:\$FolderName."
        $fallback = Join-Path 'C:\' $FolderName
        New-Item -Path $fallback -ItemType Directory -Force | Out-Null
        return $fallback
    }
}

<#
    .SYNOPSIS
    Opens the diagnostic output folder in Explorer, when it's safe and useful to do so.

    .DESCRIPTION
    Only opens Explorer when the caller asked for it AND there's an
    interactive desktop session AND the process isn't running as SYSTEM -
    an Intune-pushed run meets none of those, so it stays silent instead of
    popping a window on whoever happens to be logged on.
#>
function Show-DiagnosticFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [bool]$OpenFolder = $true
    )

    if ($OpenFolder -and [Environment]::UserInteractive -and -not (Test-RunningAsSystem)) {
        Start-Process explorer.exe $Path -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function Get-LoggedOnUserProfile, Test-RunningAsSystem, Resolve-DiagnosticOutputPath, Show-DiagnosticFolder
