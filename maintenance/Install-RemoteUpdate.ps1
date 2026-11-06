[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$template = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'RemoteUpdate.template.ps1'))
$baseline = '2026-11-06T00:00:00Z'
$files = @(git -C $root ls-files '*.ps1' '*.psm1' '*.bat' | Where-Object { $_ -notlike 'maintenance/*' })
if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate tracked scripts.' }
$powershellFiles = @($files | Where-Object { $_ -match '\.ps(m)?1$' })
foreach ($batch in ($files | Where-Object { $_ -match '\.bat$' })) {
    $path = Join-Path $root $batch
    $text = [IO.File]::ReadAllText($path)
    $text = [regex]::Replace($text, '(?ms)^REM BEGIN SCRIPT LIBRARY REMOTE UPDATE\r?\n.*?^REM END SCRIPT LIBRARY REMOTE UPDATE\r?\n', '')
    $batchParent=Split-Path $batch -Parent
    $batchCompanions=@($powershellFiles | Where-Object { (Split-Path $_ -Parent) -eq $batchParent -and $text.Contains([IO.Path]::GetFileName($_)) })
    if($batchCompanions.Count -ne 1) { throw "Launcher requires exactly one PowerShell companion: $batch" }
    $companionName=[IO.Path]::GetFileName($batchCompanions[0]).Replace("'","''")
    $preamble = @'
REM BEGIN SCRIPT LIBRARY REMOTE UPDATE
@echo off
set "SCRIPT_LIBRARY_ACTIVE_LAUNCHER=%~f0"
REM Apply a staged update before CMD reads the rest of this launcher.
if exist "%~f0.update.pending" (
    powershell.exe -NoProfile -NonInteractive -Command "try { $p=$env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER; $c=Join-Path (Split-Path $p -Parent) '__COMPANION__'; $s=Get-AuthenticodeSignature -LiteralPath $c -ErrorAction Stop; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315'){throw 'Approved companion signature required.'}; & $c -LibraryPendingBatch $p; exit $LASTEXITCODE } catch { Write-Error $_; exit 1 }"
    if errorlevel 1 exit /b 1
    call "%~f0" %*
    call exit /b %%errorlevel%%
)
REM END SCRIPT LIBRARY REMOTE UPDATE
'@
    $newline = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $preamble = $preamble.Replace('__COMPANION__',$companionName).Replace("`r`n", "`n").Replace("`n", $newline)
    [IO.File]::WriteAllText($path, ($preamble + $newline + $text), (New-Object Text.UTF8Encoding($false)))
}
$launchers = @{}
foreach ($batch in ($files | Where-Object { $_ -match '\.bat$' })) {
    $text = [IO.File]::ReadAllText((Join-Path $root $batch))
    $parent = Split-Path $batch -Parent
    $matchingTargets = @($powershellFiles | Where-Object {
        (Split-Path $_ -Parent) -eq $parent -and $text.Contains([IO.Path]::GetFileName($_))
    })
    if ($matchingTargets.Count -eq 0) { throw "No PowerShell target found for $batch" }
    foreach ($target in $matchingTargets) {
        if (-not $launchers.ContainsKey($target)) { $launchers[$target] = @() }
        $launchers[$target] += $batch
    }
}
foreach ($file in $powershellFiles) {
    $path = Join-Path $root $file
    $bytes = [IO.File]::ReadAllBytes($path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
    $text = [IO.File]::ReadAllText($path)
    $newline = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $text = [regex]::Replace($text, '(?ms)\r?\n# BEGIN SCRIPT LIBRARY REMOTE UPDATE\r?\n.*?^# END SCRIPT LIBRARY REMOTE UPDATE\r?\n\r?\n', '')
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Existing syntax errors in $file" }
    if ($launchers.ContainsKey($file) -and $null -eq $ast.ParamBlock) {
        $paramOffset=$ast.EndBlock.Statements[0].Extent.StartOffset
        $safetyMarker=$text.IndexOf('# BEGIN SCRIPT LIBRARY SAFETY')
        if($safetyMarker -ge 0 -and $safetyMarker -lt $paramOffset) { $paramOffset=$safetyMarker }
        $text=$text.Insert($paramOffset,'[CmdletBinding(SupportsShouldProcess)]' + $newline + 'param()' + $newline)
        $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    }
    if ($launchers.ContainsKey($file) -and @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'LibraryPendingBatch' }).Count -eq 0) {
        $addition=if($ast.ParamBlock.Parameters.Count) { ',' + $newline } else { '' }
        $addition+='    [Parameter(DontShow)][string]$LibraryPendingBatch' + $newline
        $text=$text.Insert($ast.ParamBlock.Extent.EndOffset-1,$addition)
        $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    }
    $offset = if ($ast.BeginBlock) {
        # Insert inside BEGIN, preserving advanced script BEGIN/PROCESS/END syntax.
        $ast.BeginBlock.Extent.StartOffset + $ast.BeginBlock.Extent.Text.IndexOf('{') + 1
    } elseif ($ast.ParamBlock) { $ast.ParamBlock.Extent.EndOffset } else {
        # Preserve leading help comments and #requires directives.
        $ast.EndBlock.Statements[0].Extent.StartOffset
    }
    $escaped = $file.Replace("'", "''")
    $calls = "    Update-LibraryScript -LocalPath `$PSCommandPath -RepositoryPath '$escaped' -Baseline '$baseline'"
    if ($launchers.ContainsKey($file)) {
        foreach ($batch in $launchers[$file]) {
            $name = [IO.Path]::GetFileName($batch).Replace("'", "''")
            $repoPath = $batch.Replace("'", "''")
            $batchHash = (Get-FileHash -LiteralPath (Join-Path $root $batch) -Algorithm SHA256).Hash
            $calls += "`n    if (Test-Path -LiteralPath (Join-Path `$PSScriptRoot '$name')) { Update-LibraryScript -LocalPath (Join-Path `$PSScriptRoot '$name') -RepositoryPath '$repoPath' -Baseline '$baseline' -ExpectedSha256 '$batchHash' }"
        }
    }
    $block = $template.Replace('    # UPDATE INVOCATIONS', $calls)
    if ($launchers.ContainsKey($file)) {
        $approved=@()
        foreach($batch in $launchers[$file]) {
            $approved += ("    '" + [IO.Path]::GetFileName($batch).Replace("'","''") + "' = '" + (Get-FileHash -LiteralPath (Join-Path $root $batch) -Algorithm SHA256).Hash + "'")
        }
        $handler=@'
if ($LibraryPendingBatch) {
    if ($WhatIfPreference) { return }
    $approvedLaunchers = @{
__APPROVED__
    }
    $batchPath=[IO.Path]::GetFullPath($LibraryPendingBatch)
    $name=[IO.Path]::GetFileName($batchPath)
    if (-not $approvedLaunchers.ContainsKey($name) -or $batchPath -ne (Join-Path $PSScriptRoot $name)) { throw 'Pending batch target is not an approved companion.' }
    $pendingPath=$batchPath+'.update.pending'
    foreach($candidate in @($batchPath,$pendingPath)) {
        if (((Get-Item -LiteralPath $candidate -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse-point batch updates are rejected.' }
    }
    if ((Get-FileHash -LiteralPath $pendingPath -Algorithm SHA256 -ErrorAction Stop).Hash -ne $approvedLaunchers[$name]) { throw 'Staged batch hash is not approved by this signed companion.' }
    [IO.File]::Replace($pendingPath,$batchPath,($batchPath+'.bak'))
    exit 0
}
'@
        $handler=$handler.Replace('__APPROVED__',($approved -join $newline))
        # Keep signature verification before the internal batch callback.
        $block=$block.Replace('& {',$handler + $newline + '& {')
    }
    $block = $block.Replace("`r`n", "`n").Replace("`n", $newline)
    $updated = $text.Insert($offset, ($newline + $block + $newline))
    $null = [Management.Automation.Language.Parser]::ParseInput($updated, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Injection introduced syntax errors in ${file}: $errors" }
    [IO.File]::WriteAllText($path, $updated, (New-Object Text.UTF8Encoding($bom)))
}
Write-Host "Installed remote updating in $($powershellFiles.Count) PowerShell files; $($launchers.Values.Count) launcher mappings."


# SIG # Begin signature block
# MIIV9QYJKoZIhvcNAQcCoIIV5jCCFeICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCGGOypE2MvJo7F
# dfCbK2bmw4qoIbVqsbFUlzlnAh+PEqCCEkQwggeJMIIGcaADAgECAhMSACPBoT1C
# 4JRtz1HgAAAAI8GhMA0GCSqGSIb3DQEBCwUAMD4xEzARBgoJkiaJk/IsZAEZFgNu
# ZXQxEzARBgoJkiaJk/IsZAEZFgNkb2kxEjAQBgNVBAMTCURPSUlNQ0EzMTAeFw0y
# NjExMDYyMDEwNTlaFw0yNzExMDYyMDEwNTlaMIGLMQswCQYDVQQGEwJVUzELMAkG
# A1UECBMCV0ExDzANBgNVBAcTBllha2ltYTEfMB0GA1UEChMWRGVwYXJ0bWVudCBv
# ZiBJbnRlcmlvcjETMBEGA1UEAxMKU2FtIENhcm1hbjEoMCYGCSqGSIb3DQEJARYZ
# c2FtdWFsX2Nhcm1hbkBpb3MuZG9pLmdvdjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALMB65QhABf/6ERNshPoYKlz/TAexeE83Pa9aTLqWhLBEeryccgp
# l7KAYxxNYP06e3SrZbPX02oExjHdcMFYQohXp3d9HWKhfRcsKEAlL8WmgI3TG9Fp
# LS1Hxf+bpSXXIa3FS133UVA6mqX0HtCnX4nKkn8gVrDQ/Ar1G0ZMg2psHpTFxfEn
# GVfz1CTjXBCKUE0uq3tZeRZJkPbqihGXCdk26l7BInFKJHExpHDg2M9BJu38/2QX
# vAQ/rdt49qAQRvWYjbblOji0gr0iMOpPVY+9YKuDjOtWQxuinz94sqWpnjAGFVvf
# bGvRV0o4INW45RKoXIsxSz9YNJ5e5HdMA6o9sXo5gtRJ19Rb6x9MtmBBEr8FFKXE
# XFD+yY8by5Xt56szifqPNw9Acbruhxw1rDw1ClvtQGg7KS01eqI9Ist6e3WhEu3N
# 0zOv+IkK2CqGCptbo2XECuPW5t1s2O9VjdAImEgAeDMwQ96g80YXqWSC5DeFBoip
# CtR9SOQGfjokVlRs1b8ZshA7SjgYwdu6BmE0JOXZxrwiS2nLdHcQwAxfBOWLUUee
# 8vowIDrpPPHGnQkNBLqfZV8E9vANo3x1m+y4QVRkiu2Yci025aQn0CnP1y9CW+i7
# S7r43ZwrHz27s2U73t42hXjWIF5IvtTQ9EL1Hal68XV0KqgwSuZDv/MtAgMBAAGj
# ggMwMIIDLDALBgNVHQ8EBAMCB4AwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUI
# hd7VSaKCaIephyOH3YdMg7XXKIEgh5imTYe8nh4CAWQCASEwHQYDVR0OBBYEFOGp
# f7zHzoQZrBDnh/y41vVsuJDrMB8GA1UdIwQYMBaAFJ13VgBe0Gl5e1vAFWdt81nx
# QGBUMIIBMAYDVR0fBIIBJzCCASMwggEfoIIBG6CCAReGgbFsZGFwOi8vL0NOPURP
# SUlNQ0EzMSxDTj1JSU5ERU5JTUNBMzEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUy
# MFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZG9pLERD
# PW5ldD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9
# Y1JMRGlzdHJpYnV0aW9uUG9pbnSGNGh0dHA6Ly9JSU5ERU5JTUNBMzEuZG9pLm5l
# dC9DZXJ0RW5yb2xsL0RPSUlNQ0EzMS5jcmyGK2h0dHA6Ly9wa2kuZG9pLm5ldC9D
# ZXJ0RW5yb2xsL0RPSUlNQ0EzMS5jcmwwggE2BggrBgEFBQcBAQSCASgwggEkMIGk
# BggrBgEFBQcwAoaBl2xkYXA6Ly8vQ049RE9JSU1DQTMxLENOPUFJQSxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPWRvaSxEQz1uZXQ/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNl
# cnRpZmljYXRpb25BdXRob3JpdHkwVQYIKwYBBQUHMAKGSWh0dHA6Ly9JSU5ERU5J
# TUNBMzEuZG9pLm5ldC9DZXJ0RW5yb2xsL0lJTkRFTklNQ0EzMS5kb2kubmV0X0RP
# SUlNQ0EzMS5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRvaS5nb3Yvb2Nz
# cDATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUF
# BwMDMA0GCSqGSIb3DQEBCwUAA4IBAQAJy0oIvD1YUCHaYMzqmkmAf3fGgKl5LXr4
# nrzVUQ8NyqOVOofS5yJFeVH1S3MYdQddy6t2qWrMrdpEuDp91VmRTOJGyNZByj22
# 3VKoBtlmVPtE2lpKmioOvvRcodTTbWFstxWBVXHAtU9zCJ6wIQonjpyz9qCctaN/
# 0s7urcD2YUk7MvcwKEJQxGVDyxt8qxpptFQlZpdIbAqVac6lvoIU93GSOr5/dkIW
# aIC9TNsTW2MxxuhaJ8+lLsqeAqt+TH10/CeZHfMdeBgBS7QJRFH0Nx7H1VcL1plO
# KAnKz7CRc+TNDqOmvesmLG4t0sfUmMcylWLBYeyU72asqmm1UfDZMIIKszCCCJug
# AwIBAgITTAAAAEJP4Xkdf3hC8QAAAAAAQjANBgkqhkiG9w0BAQsFADAVMRMwEQYD
# VQQDEwpET0lSb290Q0EyMB4XDTIzMDYyNjE5MjEyMloXDTI4MDYyNjE5MzEyMlow
# PjETMBEGCgmSJomT8ixkARkWA25ldDETMBEGCgmSJomT8ixkARkWA2RvaTESMBAG
# A1UEAxMJRE9JSU1DQTMxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# rR6hbj0t+mKgdcJczlzU6OWcfMspR1izM2Y5nmtjcqV+yznzO3HvCSfPDyZN9seq
# u+Omjv/axQSJDHKb9ynyt5f9UafC9PoDKxGucmIQqfYMM/CRtS3F4uU3S5wAXNTv
# ROfbpieGWRK/AgaEIeIbgHBgW9NNS+krQEhG2TTcBdn3NzNVREjKezYwi/oQ35SD
# ePu1T8rtyLbBq6JLI5gGCfycX7ZgQcXKzBQJpf0ovlgYSSdWvliRRTIiNvJexxjE
# HCLhH3qJMKgYkJAlqQ9Qq9JPFurdwQv3E/uI+6aZP5S/9HyT+ZyN9lpdlPQMZByJ
# 7H6uWSsIvtXtnZVMQe3e/wIDAQABo4IG0TCCBs0wEAYJKwYBBAGCNxUBBAMCAQAw
# HQYDVR0OBBYEFJ13VgBe0Gl5e1vAFWdt81nxQGBUMIIE6wYDVR0gBIIE4jCCBN4w
# ggIOBglghkgBZQMCARMwggH/MC8GCCsGAQUFBwIBFiNodHRwOi8vcGtpMi5kb2ku
# bmV0L2xlZ2FscG9saWN5LmFzcDCCAcoGCCsGAQUFBwICMIIBvB6CAbgAQwBlAHIA
# dABpAGYAaQBjAGEAdABlACAAaQBzAHMAdQBlAGQAIABiAHkAIAB0AGgAZQAgAEQA
# ZQBwAGEAcgB0AG0AZQBuAHQAIABvAGYAIAB0AGgAZQAgAEkAbgB0AGUAcgBpAG8A
# cgAgAGEAcgBlACAAbwBuAGwAeQAgAGYAbwByACAAaQBuAHQAZQByAG4AYQBsACAA
# dQBuAGMAbABhAHMAcwBpAGYAaQBlAGQAIABVAFMAIABHAG8AdgBlAHIAbgBtAGUA
# bgB0ACAAdQBzAGUAIABhAGwAbAAgAG8AdABoAGUAcgAgAHUAcwBlACAAaQBzACAA
# cAByAG8AaABpAGIAaQB0AGUAZAAuACAAVQBuAGEAdQB0AGgAbwByAGkAegBlAGQA
# IAB1AHMAZQAgAG0AYQB5ACAAcwB1AGIAagBlAGMAdAAgAHYAaQBvAGwAYQB0AG8A
# cgBzACAAdABvACAAYwByAGkAbQBpAG4AYQBsACwAIABjAGkAdgBpAGwAIABhAG4A
# ZAAvAG8AcgAgAGQAaQBzAGMAaQBwAGwAaQBuAGEAcgB5ACAAYQBjAHQAaQBvAG4A
# LjCCAsgGCmCGSAFlAwIBEwEwggK4MDQGCCsGAQUFBwIBFihodHRwOi8vcGtpMi5k
# b2kubmV0L2xpbWl0ZWR1c2Vwb2xpY3kuYXNwMIICfgYIKwYBBQUHAgIwggJwHoIC
# bABVAHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUA
# IABpAHMAIABsAGkAbQBpAHQAZQBkACAAdABvACAASQBuAHQAZQByAG4AYQBsACAA
# RwBvAHYAZQByAG4AbQBlAG4AdAAgAHUAcwBlACAAYgB5ACAALwAgAGYAbwByACAA
# dABoAGUAIABEAGUAcABhAHIAdABtAGUAbgB0ACAAbwBmACAAdABoAGUAIABJAG4A
# dABlAHIAaQBvAHIAIABvAG4AbAB5ACEAIABFAHgAdABlAHIAbgBhAGwAIAB1AHMA
# ZQAgAG8AcgAgAHIAZQBjAGUAaQBwAHQAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIA
# dABpAGYAaQBjAGEAdABlACAAcwBoAG8AdQBsAGQAIABuAG8AdAAgAGIAZQAgAHQA
# cgB1AHMAdABlAGQALgAgAEEAbABsACAAcwB1AHMAcABlAGMAdABlAGQAIABtAGkA
# cwB1AHMAZQAgAG8AcgAgAGMAbwBtAHAAcgBvAG0AaQBzAGUAIABvAGYAIAB0AGgA
# aQBzACAAYwBlAHIAdABpAGYAaQBjAGEAdABlACAAcwBoAG8AdQBsAGQAIABiAGUA
# IAByAGUAcABvAHIAdABlAGQAIABpAG0AbQBlAGQAaQBhAHQAZQBsAHkAIAB0AG8A
# IABhACAARABlAHAAYQByAHQAbQBlAG4AdAAgAG8AZgAgAHQAaABlACAASQBuAHQA
# ZQByAGkAbwByACAAUwBlAGMAdQByAGkAdAB5ACAATwBmAGYAaQBjAGUAcgAuMBkG
# CSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8E
# BTADAQH/MB8GA1UdIwQYMBaAFL+GK8rzbG0+Xxw7Tk7Yjedqx2pPMIH4BgNVHR8E
# gfAwge0wgeqggeeggeSGgbJsZGFwOi8vL0NOPURPSVJvb3RDQTIsQ049SUlOREVO
# T1JDQTAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2
# aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRvaSxEQz1uZXQ/Y2VydGlmaWNhdGVS
# ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
# aW50hi1odHRwOi8vcGtpMi5kb2kubmV0L0NlcnRFbnJvbGwvRE9JUm9vdENBMi5j
# cmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vcGtpMi5kb2ku
# bmV0L0NlcnRFbnJvbGwvSUlOREVOT1JDQTAxX0RPSVJvb3RDQTIuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQDG7R1D09znHx+f/ZFYA3cn9RxQdNuwfjksZqLHCJM+w5y8
# zvNXrSy7sNFfenK/OtKvC88SJ2ToSLwgZ4OXCvYWuKqvZGsBsY0/asFLBY2uitwo
# fOHHIUfO37ZtG3nc4vDluHghNYafPdPu1IetbWC6ZX0oasVV23OiAeG0tYzt2sVM
# NU5sqRoLZxLtqaAV/Kb6scnJH+R/wxEUxSgnZkxlV/4K+PnYWmeAgM1/PKXNRk3M
# 6gZYZ9EkBt40FtR8M99NF/5YinvyaEhDWuilG8cjxYmY6z8q1rrv+TNL2rpfUi65
# bR26F/0jHrctTpp1anASAHztaSt5dUMDw3sk8tiYpbGbvu6859B6BgP0cbKb3T75
# SOtvJjcnZZaapPDxMPv+itH7zrzrcH1CX7TilxUCAFKd6GizIrSCO+1Rfl5zcrLL
# vxb4oxOz0763X/6e8CXYZM92vXzZlicSwk90qaXA6H2BJWNXxec8YzFw57OGTJBM
# 7lzUFagPkcSUhXZDesdQik94dFvxgMz8NVB0EuJK1+8XwQjfoQfAEtFW0nnZHUgZ
# yn5TkqFFvVbIBRQ6U1fUS3g5WzYfYfnmYKG1VCk2X+43KZcuC7AW/JxwAic+hKxS
# Ie5bTR2fxpQgUT/Jr2GUTAIN14FLXOdA2GEykdJXvaJbsSzUip0lzegPKezXuDGC
# AwcwggMDAgEBMFUwPjETMBEGCgmSJomT8ixkARkWA25ldDETMBEGCgmSJomT8ixk
# ARkWA2RvaTESMBAGA1UEAxMJRE9JSU1DQTMxAhMSACPBoT1C4JRtz1HgAAAAI8Gh
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIEzTJsRQ9ntQpOkanlEtvCr2pW2n/xQdIye3
# GgxeM/nzMA0GCSqGSIb3DQEBAQUABIICAAgiKG586xxJcaP/YaugrtBUNP2S+bos
# QFbSTYuUwL23ofl23ErdNTfScKzgVVTDdalZEnGMR0EJinZrDSLVWdcHNyQYHluJ
# HcRg+sEx2ZNogeW6kDTaVNqd0lALhDI75gyXAfFLGXUGYIW5u5Ns9EA1MB2jRnx7
# Hf8ih44z7UqpDncN6kt4V/8vJyp/fxV7dfYITJa/uVYwpKnDtjn2OQnwAuCied8p
# ujmYAyi6n17tprzrt/4Ukhh//y1JQx/hzT1LY9G/XWg/81aEq4IhsSbBfXrjX9Pb
# eF6IR6dwU/a5xso3kIdlCBzRgK0itQZd/caNcjA1acAQ/TzOi/zL7XT4HNGVKZiZ
# uGiZM7DguRPlBsvs1yVMlyTkbVr4xrXJ6EpJFcQYHM2l/fTVW252NBz/0TcXzSBb
# HjWb90B0Butgs+FCsJLPaKlD0KGjuaLQ9z3TIBXn1jKFI512YpyZzo3FzbkGrzQn
# B4XoF1NEF/qbk+OFo6QKgKbY/NMpp6KF0C0TktewrGQbN4hwrpypZwBgRX+bSCyM
# aAGIMC3kPH5t8RQpn4DslHug9iXKAWZ/wEyxEBkRif+nonY5wCOgDM78iBs8X7T5
# UIDluSNsFPUniMg2pRnqrZsG/RansEeCbaADX73DSH+h67dFzcO6MhU2xUeg+pQJ
# 3gv8X94gR8qR
# SIG # End signature block
