#requires -Version 5.1
<#
.SYNOPSIS
Signs the finished library with the explicitly selected local code-signing certificate.
.DESCRIPTION
Never exports a private key, imports trust certificates, or publishes files.
Regenerate update blocks and run tests before signing. An approved timestamp
server may be supplied; without one signatures have no trusted timestamp.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315',
    [string]$TimestampServer
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$certificates = @(Get-ChildItem Cert:/CurrentUser/My,Cert:/LocalMachine/My -CodeSigningCert | Where-Object Thumbprint -eq $Thumbprint)
$certificate = $certificates | Where-Object HasPrivateKey | Select-Object -First 1
if (-not $certificate) { throw 'Selected code-signing certificate with private key was not found.' }
if ($certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date)) { throw 'Code-signing certificate is outside its validity period.' }
if ($TimestampServer) {
    $timestampUri = $null
    if (-not [uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$timestampUri) -or $timestampUri.Scheme -notin @('http','https')) {
        throw 'Provide an approved HTTP(S) Authenticode timestamp server URL.'
    }
} else { Write-Warning "No approved timestamp server supplied. Signatures will have no trusted timestamp; certificate expires $($certificate.NotAfter.ToString('yyyy-MM-dd'))." }
$tracked = @(git -C $root ls-files '*.ps1' '*.psm1')
if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate scripts.' }
$files = @(@($tracked) + @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Where-Object Name -notlike '*.template.ps1' | ForEach-Object { 'maintenance/' + $_.Name }) | Sort-Object -Unique | Where-Object { $_ -notlike 'maintenance/*.template.ps1' })
# Validate every file before changing any signature.
foreach ($relative in $files) {
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Syntax errors prevent signing: $relative" }
}
$results = @(
    foreach ($relative in $files) {
        $path = Join-Path $root $relative
        if ($PSCmdlet.ShouldProcess($relative, "Sign with certificate $Thumbprint")) {
            $arguments = @{ LiteralPath = $path; Certificate = $certificate; HashAlgorithm = 'SHA256'; ErrorAction = 'Stop' }
            if ($TimestampServer) { $arguments.TimestampServer = $TimestampServer }
            $signature = Set-AuthenticodeSignature @arguments
            [pscustomobject]@{ Path=$relative; Status=[string]$signature.Status; Thumbprint=$Thumbprint; Timestamped=($null -ne $signature.TimeStamperCertificate) }
        }
    }
)
if (-not $WhatIfPreference) {
    $output = Join-Path $PSScriptRoot 'results'
    $null = New-Item -Path $output -ItemType Directory -Force
    $results | Export-Csv -LiteralPath (Join-Path $output 'signatures.csv') -NoTypeInformation -Encoding UTF8
    if (@($results | Where-Object Status -ne 'Valid').Count) { throw 'One or more signatures failed validation. Inspect maintenance/results/signatures.csv.' }
    Write-Host "Signed and validated $($results.Count) PowerShell files with SHA-256."
}


# SIG # Begin signature block
# MIIV9QYJKoZIhvcNAQcCoIIV5jCCFeICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9eAHfo8wAdAoM
# S8gFf8yHYq029Udv9ttQwZ8oAWkVLqCCEkQwggeJMIIGcaADAgECAhMSACPBoT1C
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEII/xz5KE/ZTpNBZaaspm4TQbpNw5qCXOf1u6
# LvmDFTNbMA0GCSqGSIb3DQEBAQUABIICAC5YslY9LPXljF05S3vQLTmA7drFYTaf
# MUzgMnzYr8N6yFV161Isa7kA1+MDc5epXp6eB6w5TIXRQ+aLzFciGl6Nn2la+X0k
# JJtx+kg1il6/m64GFgAlSGDjSdSwSq+B95Q9fsMEzqyu6ZOavCNr+PP1T5+KZCEB
# hwdMHZ3lWCkWo5pvj/WC0YyBOebL48GAIr/8Z/iIwM+8IXhkKw3cgm32u1nmUwLr
# DIFC6VyOguLbSWmPqh2opStsHt5LSD2ZXeh4YA32qQYShRAVuAABhhayCkx/0VUW
# 2laD4r3Xd3HuaI3Dr0jaBJIdww7FZ/fTSxD4aa128/EN6Tw4vDiHg1W8FP3tHymx
# PJqnEro3Oe2lxgnCR8/Bz/PvRA4cAFjAiXKOgGM+KiPDCihvU/yu1GG1DcC4D400
# PSL7DGG0Qr3m9DO69SrhMic/7rPSV1dVhSVg+6PohvHI93lK13tb2am9/+5weU3d
# 9KFq94fMxhT0hbJgIScupSyds8FDmJPSVdIbJN9HOvDF817gNk2xYk6+pw1EAuv9
# q1l4/hT8ouFNzrv30/H+AVvfJJFICMy9WyUEg4I8iwo/+VGhMss7FO+6QM77Yq8M
# 5YBr3AhsbYAelDmk9tsT3qTFXizEwlwUw7xDyw24tljsziljRMtC/5mtus7hVnoQ
# V6lnn6YtMKX3
# SIG # End signature block
