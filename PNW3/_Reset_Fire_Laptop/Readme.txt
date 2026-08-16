Drop folder on a thumbdrive. Run the .bat file and it will call the PowerShell script with bypass settings.

As of v2.9, Reset_Fire_Laptop.ps1 can also be run directly (e.g. opened and run/F5'd in
PowerShell ISE, or "powershell.exe -File Reset_Fire_Laptop.ps1") without going through the
.bat first - if it isn't already running elevated, it will prompt for UAC and relaunch
itself elevated automatically.