#######################################
#You will need to have PSExec64.exe and robocopy.exe installed on your system. If they are in different locations that what is listed in the script
#then you can chage the script or place a copy in the folders listed in the script.
#Copy and paste the lines 3 to 16 into a powershell window. After the PSSession is started then copy and paste lines 18 to 35 into the same powershell session 
#IMPORTANT!!!! Be sure to change the variable $Computer and the email address before running the script
$Computers = Get-Content D:\Copy1\UpdateEdge.txt #UpdateChrome.txt  #"IBR1ABOURGOIL02"

foreach ($Computer in $Computers) {
    New-Item -Path "\\$Computer\c$\TempCH" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    robocopy "\\ibr1pnrfs001\Everyone\Everyone\Patches\edge" "\\$Computer\C$\TempCH" /mir /R:2 /W:2
    if ($LASTEXITCODE -ge 8) {
        Write-Warning "Robocopy failed on $Computer (exit $LASTEXITCODE). Skipping install."
        continue
    }

    ./psexec  \\$Computer cmd /c "msiexec.exe /I C:\TempCH\MicrosoftEdgeEnterpriseX64.msi /qb"
    ./psexec  \\$Computer cmd /c "C:\TempCH\netstop.bat"
    Start-Sleep -Seconds 5
    ./psexec  \\$Computer cmd /c "C:\TempCH\netstart.bat"

    Start-Sleep -Seconds 15

    Remove-Item -Path "\\$Computer\c$\TempCH" -Recurse -Force
}



