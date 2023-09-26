> _PsLoggedOn_ is part of a growing kit of Sysinternals command-line tools that aid in the administration of local and remote systems named _PsTools_.
> 
> _PsLoggedOn_ is an applet that displays both the locally logged on users and users logged on via resources for either the local computer, or a remote one. 
> 
> If you specify a user name instead of a computer, _PsLoggedOn_ searches the computers in the network neighborhood and tells you if the user is currently logged on.
> 
> _PsLoggedOn_'s definition of a locally logged on user is one that has their profile loaded into the Registry, so _PsLoggedOn_ determines who is logged on by scanning the keys under the HKEY_USERS key. 
> 	For each key that has a name that is a user SID (security Identifier), _PsLoggedOn_ looks up the corresponding user name and displays it. 
> 	To determine who is logged onto a computer via resource shares, _PsLoggedOn_ uses the _NetSessionEnum_ API. 
> 	
> Note that _PsLoggedOn_ will show you as logged on via resource share to remote computers that you query because a logon is required for _PsLoggedOn_ to access the Registry of a remote system.
> 
> https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite


#Active_Directory_Enumeration #Windows_Enumeration 

# Usage

Using PsLoggedOn to see user logons at Files04
```powershell
.\PsLoggedon.exe \\files69
```
- Remote Registry service needs to be enabled
- Current user will be shown as logged on via resource shares. 
	- This is shown because PsLoggedOn also uses the _NetSessionEnum_ API, which in this case requires a logon in order to work. 