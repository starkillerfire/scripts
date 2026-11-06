[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$template = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'RemoteUpdate.template.ps1'))
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($template, [ref]$tokens, [ref]$errors)
$functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Update-LibraryScript' }, $true)
. ([scriptblock]::Create($functionAst.Extent.Text))
$sandbox = Join-Path $root ('ScriptLibraryUpdateTests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $sandbox
$originalSkip = $env:SCRIPT_LIBRARY_SKIP_UPDATE
$originalLauncher = $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER
$originalGithubToken = $env:SCRIPT_LIBRARY_GITHUB_TOKEN
$originalGitlabToken = $env:SCRIPT_LIBRARY_GITLAB_TOKEN
$originalSigners = $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS
$script:checks = 0
function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
function Invoke-RestMethod {
    [CmdletBinding()]
    param($Uri, $Headers, $TimeoutSec, $MaximumRedirection)
    $script:requests += [pscustomobject]@{ Uri = $Uri; Headers = $Headers }
    $github = $Uri -like 'https://api.github.com/*'
    if ($script:scenario -eq 'offline' -or ($script:scenario -eq 'gitlab' -and $github) -or ($script:scenario -eq 'github' -and -not $github)) { throw 'Mock offline' }
    if ($script:scenario -eq 'emptyPrimary' -and -not $github) { return }
    $date = if ($script:scenario -eq 'old' -or ($script:scenario -eq 'authoritativeOld' -and -not $github)) { '2026-01-01T00:00:00Z' }
        elseif ($github) { '2026-11-07T00:00:00Z' } else { '2026-11-08T00:00:00Z' }
    if ($script:scenario -eq 'secondUpdate') { $date=$script:secondUpdateDate }
    if ($github) { [pscustomobject]@{ sha = ('a' * 40); commit = @{ committer = @{ date = $date } } } }
    elseif ($script:scenario -eq 'malformedPrimary') { [pscustomobject]@{ id = 'invalid'; committed_date = $date } }
    else { [pscustomobject]@{ id = ('b' * 40); committed_date = $date } }
}
function Get-AuthenticodeSignature {
    [CmdletBinding()]
    param($LiteralPath)
    $isDownload = $LiteralPath -match '\.download\.'
    if ($script:scenario -eq 'localInvalid') { return [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null} }
    if ($script:scenario -eq 'localUnsigned') { return [pscustomobject]@{Status='NotSigned';SignerCertificate=$null} }
    if ($script:scenario -eq 'localWrong') { return [pscustomobject]@{Status='Valid';SignerCertificate=@{Thumbprint=('D'*40)}} }
    if ($script:scenario -eq 'signedDowngrade' -and $isDownload) {
        [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }
    } elseif ($script:scenario -eq 'signedDowngrade' -and -not $isDownload) {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } }
    } elseif ($script:scenario -eq 'signedApproved') {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } }
    } elseif ($script:scenario -eq 'signedWrong' -and $isDownload) {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = ('D' * 40) } }
    } else { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } } }
}
function Invoke-WebRequest {
    [CmdletBinding()]
    param($Uri, $Headers, [switch]$UseBasicParsing, $OutFile, $TimeoutSec, $MaximumRedirection)
    $script:downloads += $Uri
    if ($script:scenario -eq 'fallback' -and $Uri -like 'https://gitlab*') { throw 'Mock failed download' }
    $payload = switch ($script:scenario) {
        'html' { '<html>Login required</html>' }
        'invalid' { "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nfunction {" }
        'legacy' { 'Write-Output legacy' }
        'identical' { $script:original }
        'batch' { $script:batchPayload }
        'secondUpdate' { $script:secondUpdatePayload }
        default { "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'updated'" }
    }
    [IO.File]::WriteAllText($OutFile, $payload)
}
try {
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $null
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $null
    $env:SCRIPT_LIBRARY_GITHUB_TOKEN = 'mock-github-token'
    $env:SCRIPT_LIBRARY_GITLAB_TOKEN = 'mock-gitlab-token'
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $null
    foreach ($scenario in @('offline', 'old', 'newest', 'gitlab', 'github', 'fallback', 'authoritativeOld', 'emptyPrimary', 'malformedPrimary', 'html', 'invalid', 'legacy', 'identical', 'signedDowngrade', 'signedWrong', 'signedApproved')) {
        $script:scenario = $scenario
        $script:requests = @()
        $script:downloads = @()
        $file = Join-Path $sandbox ($scenario + '.ps1')
        $script:original = "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'original'"
        [IO.File]::WriteAllText($file, $script:original)
        $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = if ($scenario -eq 'signedWrong') { 'C' * 40 } else { $null }
        Update-LibraryScript -LocalPath $file -RepositoryPath 'Folder With Spaces/Script.ps1' -Baseline '2026-11-06T00:00:00Z' -WarningAction SilentlyContinue
        $expectedChecks = if ($scenario -in @('offline','github')) { 2 } else { 1 }
        Assert-True ($script:requests.Count -eq $expectedChecks) "$scenario checks secondary only when primary is unavailable"
        Assert-True ($script:requests[0].Uri -like 'https://gitlab.bor.doi.net/*') 'GitLab checked first'
        foreach ($request in $script:requests) {
            if ($request.Uri -like 'https://api.github.com/*') { Assert-True (-not $request.Headers.ContainsKey('PRIVATE-TOKEN')) 'GitLab token never sent to GitHub' }
            else { Assert-True (-not $request.Headers.ContainsKey('Authorization')) 'GitHub token never sent to GitLab' }
        }
        if ($scenario -in @('newest', 'gitlab', 'github', 'signedApproved')) {
            Assert-True (([IO.File]::ReadAllText($file)) -match 'updated') "$scenario replaces installed script"
            Assert-True (([IO.File]::ReadAllText($file + '.bak')) -eq $script:original) "$scenario preserves backup"
            $state = Get-Content -LiteralPath ($file + '.update.json') -Raw | ConvertFrom-Json
            $expected = if ($scenario -eq 'github') { 'GitHub' } else { 'GitLab' }
            Assert-True ($state.Source -eq $expected) "$scenario selects correct provider"
            $script:downloads = @()
            Update-LibraryScript -LocalPath $file -RepositoryPath 'Folder With Spaces/Script.ps1' -Baseline '2026-11-06T00:00:00Z' -WarningAction SilentlyContinue
            Assert-True ($script:downloads.Count -eq 0) "$scenario avoids reinstalling recorded commit"
        } else {
            Assert-True (([IO.File]::ReadAllText($file)) -eq $script:original) "$scenario preserves existing script"
            Assert-True (-not (Test-Path -LiteralPath ($file + '.bak'))) "$scenario does not create backup"
        }
    }
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = '1'
    $script:requests = @()
    Update-LibraryScript -LocalPath $file -RepositoryPath 'skip.ps1' -Baseline '2026-11-06T00:00:00Z'
    Assert-True ($script:requests.Count -eq 0) 'Disable flag prevents network requests'
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $null
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $null
    $guard=[regex]::Match($template,'(?ms)^# Verify the installed file.*?(?=^& \{)').Value.Replace('$PSCommandPath',"'fixture.ps1'")
    foreach($scenario in @('localInvalid','localUnsigned','localWrong')) {
        $script:scenario=$scenario;$script:operationalReached=$false;$blocked=$false
        try { & ([scriptblock]::Create($guard+"`n"+'$script:operationalReached=$true')) } catch { $blocked=$true }
        Assert-True ($blocked -and -not $script:operationalReached) "$scenario rejected before operational code"
    }
    $script:scenario='newest';$script:operationalReached=$false
    & ([scriptblock]::Create($guard+"`n"+'$script:operationalReached=$true'))
    Assert-True $script:operationalReached 'Approved local signature allows operational code'
    $script:scenario='secondUpdate';$script:secondUpdateDate='2026-11-10T00:00:00Z'
    $script:secondUpdatePayload="# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'first revision'"
    $twiceFile=Join-Path $sandbox 'two-updates.ps1'
    [IO.File]::WriteAllText($twiceFile,$script:original)
    Update-LibraryScript -LocalPath $twiceFile -RepositoryPath 'two-updates.ps1' -Baseline '2026-11-06T00:00:00Z'
    $firstRevision=$script:secondUpdatePayload
    $script:secondUpdateDate='2026-11-11T00:00:00Z';$script:secondUpdatePayload="# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'second revision'"
    Update-LibraryScript -LocalPath $twiceFile -RepositoryPath 'two-updates.ps1' -Baseline '2026-11-06T00:00:00Z'
    Assert-True (([IO.File]::ReadAllText($twiceFile)) -eq $script:secondUpdatePayload) 'Second update replaces first revision'
    Assert-True (([IO.File]::ReadAllText($twiceFile+'.bak')) -eq $firstRevision) 'Second update retains the prior revision'
    $twiceState=Get-Content -LiteralPath ($twiceFile+'.update.json') -Raw | ConvertFrom-Json
    Assert-True ([datetimeoffset]$twiceState.CommittedAt -eq [datetimeoffset]$script:secondUpdateDate) 'State advances on subsequent updates'
    $script:requests = @()
    Update-LibraryScript -LocalPath $file -RepositoryPath 'preview.ps1' -Baseline '2026-11-06T00:00:00Z' -WhatIf
    Assert-True ($script:requests.Count -eq 0) 'WhatIf does not check, download, or replace updates'

    # Exercise the actual CMD preamble without running any administrative script.
    $batchText = [IO.File]::ReadAllText((Join-Path $root 'Autopilot/Autopilot-v2.bat'))
    $preamble = [regex]::Match($batchText, '(?ms)^REM BEGIN SCRIPT LIBRARY REMOTE UPDATE.*?^REM END SCRIPT LIBRARY REMOTE UPDATE\r?\n').Value
    Assert-True ($preamble.Length -gt 0) 'Batch launcher contains safe-update preamble'
    $batch = Join-Path $sandbox 'launcher.bat'
    $oldBatch = $preamble + "@echo off`r`necho OLD`r`nexit /b 7`r`n"
    $script:batchPayload = $preamble + "@echo off`r`necho NEW`r`nexit /b 9`r`n"
    # A synthetic signed companion exercises the actual authenticated CMD callback.
    $fixtureHashPath=Join-Path $sandbox 'callback-payload.txt'
    [IO.File]::WriteAllText($fixtureHashPath,$script:batchPayload)
    $fixtureHash=(Get-FileHash -LiteralPath $fixtureHashPath -Algorithm SHA256).Hash
    $callback=Join-Path $sandbox 'Autopilot-v2.ps1'
    $callbackText=@'
param([string]$LibraryPendingBatch)
if((Get-FileHash -LiteralPath ($LibraryPendingBatch+'.update.pending') -Algorithm SHA256).Hash -ne '__HASH__'){throw 'Invalid fixture hash'}
[IO.File]::Replace(($LibraryPendingBatch+'.update.pending'),$LibraryPendingBatch,($LibraryPendingBatch+'.bak'))
exit 0
'@
    [IO.File]::WriteAllText($callback,$callbackText.Replace('__HASH__',$fixtureHash),(New-Object Text.UTF8Encoding($true)))
    $fixtureCertificate=Get-Item Cert:/CurrentUser/My/CEFA4DF2F31F5218A3F3B28144AFD9A96770A315
    $fixtureSignature=Set-AuthenticodeSignature -LiteralPath $callback -Certificate $fixtureCertificate -HashAlgorithm SHA256
    Assert-True ($fixtureSignature.Status -eq 'Valid') 'Synthetic batch companion signature validates'
    [IO.File]::WriteAllText($batch, $oldBatch)
    $script:scenario = 'batch'
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $batch
    $hashPath = Join-Path $sandbox 'approved-batch.txt'
    [IO.File]::WriteAllText($hashPath, $script:batchPayload)
    $batchHash = (Get-FileHash -LiteralPath $hashPath -Algorithm SHA256).Hash
    Update-LibraryScript -LocalPath $batch -RepositoryPath 'launcher.bat' -Baseline '2026-11-06T00:00:00Z' -ExpectedSha256 ('0' * 64) -WarningAction SilentlyContinue
    Assert-True (-not (Test-Path -LiteralPath ($batch + '.update.pending'))) 'Unapproved batch hash is rejected'
    Update-LibraryScript -LocalPath $batch -RepositoryPath 'launcher.bat' -Baseline '2026-11-06T00:00:00Z' -ExpectedSha256 $batchHash
    Assert-True (([IO.File]::ReadAllText($batch)) -eq $oldBatch) 'Running batch remains unchanged'
    Assert-True (Test-Path -LiteralPath ($batch + '.update.pending')) 'Running batch update is staged'
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $env:ComSpec
    $start.Arguments = '/d /c .\launcher.bat'
    $start.WorkingDirectory = $sandbox
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $batchExit = $process.ExitCode
    $process.Dispose()
    Assert-True ($batchExit -eq 9) "Updated batch preserves exit code (actual $batchExit; output $output)"
    Assert-True ($output -match '(?m)^NEW\r?$') 'Next batch launch executes updated body'
    Assert-True (([IO.File]::ReadAllText($batch + '.bak')) -eq $oldBatch) 'Batch update retains backup'
    Assert-True (-not (Test-Path -LiteralPath ($batch + '.update.pending'))) 'Staged update consumed'

    $tracked = @(git -C $root ls-files '*.ps1' '*.psm1' | Where-Object { $_ -notlike 'maintenance/*' })
    foreach ($relative in $tracked) {
        $path = Join-Path $root $relative
        $text = [IO.File]::ReadAllText($path)
        $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "Syntax valid: $relative"
        Assert-True (([regex]::Matches($text, '(?m)^# BEGIN SCRIPT LIBRARY REMOTE UPDATE')).Count -eq 1) "Exactly one update block: $relative"
    }
    Write-Host "PASS: $script:checks assertions; mocked update and batch tests; all library scripts parsed."
} finally {
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $originalSkip
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $originalLauncher
    $env:SCRIPT_LIBRARY_GITHUB_TOKEN = $originalGithubToken
    $env:SCRIPT_LIBRARY_GITLAB_TOKEN = $originalGitlabToken
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $originalSigners
    # Delete only the unique test directory verified beneath this workspace.
    $resolved = [IO.Path]::GetFullPath($sandbox)
    $tempRoot = [IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'ScriptLibraryUpdateTests-*') {
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try { Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop; break }
            catch { if ($attempt -eq 5) { throw }; Start-Sleep -Milliseconds 300 }
        }
    }
}


# SIG # Begin signature block
# MIIV9QYJKoZIhvcNAQcCoIIV5jCCFeICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDLJ6H1GQxtj9Br
# LxGALZhiNRXjZ+3xVpjUopFwRIIPUaCCEkQwggeJMIIGcaADAgECAhMSACPBoT1C
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
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIFkHviQyA1Z0UUStWQ+XQEKS4lmZGhdxO31H
# JlNeiyGsMA0GCSqGSIb3DQEBAQUABIICABFLvanWOcBdsUtrN/4EukFapfFIgRj4
# ScLE5QgqgR/jlLmf6oFUWVvPxnIqjaMbPhMPAAX/D9XBP5hB4S8/YrsiZuUr/rT0
# 14U1nnjU0VkGAkfurg/GsSZtbGtRuhoxZlG+vsMV+aAC4fM2GpW2D8G02p6TBfPg
# B1MvW54tzjDPdApfAlpcox0P4dw73BTgHIA6iGAn0YyFo4QV1fNaerM5nHxrnM6y
# niWW4VyDZeRe3cH8ShOOowIgg7cjNFUvwejf6DrBUZQTgggP8k7GkWbrUAM3K1rp
# xvR2ECgPg1Jm9pJqO+rmpMhHRS7MHDms4w6i9MmTpxk8taNJNqpiJH5ZLeRlCTZY
# cqN+bxcCQ44tY+W7k0uKZ87ltJvRHM5ZPPAxZgkUQMg7OHJK2oBHekorcy7Kv/h4
# 8K8izD79uB9U1jZYg/t8w+LHEm4q4EImGmY3z7dJSMoyAiKKKNM1jnBwggoKya+l
# SC8TmB5BifgKld3dhnM/rZjxnOh7LkYHq/wxisRhI6LuLOUCgdqDZWnvJCrRfsQH
# ko9T5nlrLCT7IMcsA6BmyZ64dg2ZEhLecTYteaAb1FFTRJDmSdZ4VJ4NqnttVlKs
# WNAI1+O4XRnpGz27sjpuB2xQ11ng4uEw7Nv9quQUlA15n6G3vl7/+iQNkzL+EgNd
# 0CznNgQjJAje
# SIG # End signature block
