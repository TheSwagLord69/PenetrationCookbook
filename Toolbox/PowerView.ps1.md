> a PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "`net *`" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.

#Active_Directory_Enumeration 

# Binary Location

Copy to working directory
```
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
```

# Usage

Import `PowerView.ps1`
```powershell
. .\PowerView.ps1
```

Obtain domain information
```powershell
Get-NetDomain
```

Get a list of all domain user accounts
```powershell
Get-NetUser
```

Query all domain users displaying cn, pwdlastset and lastlogon
```powershell
Get-NetUser | select cn,pwdlastset,lastlogon
```

List all the SPN accounts in the domain
```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

Get a list of all groups in the domain
```powershell
Get-NetGroup | select cn
```

Show members of domain group E.g., Sales Department
```powershell
Get-NetGroup "Sales Department" | select member
```

Enumerate the computer objects in the domain
```powershell
Get-NetComputer
```

Display properties of computers E.g., hostname, OS and version
```powershell
Get-NetComputer | select samaccountname, dnshostname, operatingsystem, operatingsystemversion
```

Enumerates the domain controllers for the current or specified domain
```powershell
Get-NetDomainController
```

Get IP address of domain computer E.g., files69
```powershell
Resolve-IPAddress -ComputerName files69
```

Find machines in the domain where the current user has local administrator access
```powershell
Find-LocalAdminAccess
```

Checking logged on users (active sessions) on local or remote machine
```powershell
Get-NetSession -ComputerName files69 -Verbose
```
- By default, PowerView uses query level 10 with _NetSessionEnum_
	- Five possible query levels: 0,1,2,10,502. 
		- Level 0 only returns the name of the computer establishing the session. 
		- Levels 1 and 2 return more information but require administrative privileges.
		- Levels 10 and 502 should return information such as the name of the computer and name of the user establishing the connection. 
- Permissions required to enumerate sessions with _NetSessionEnum_ are defined in the **SrvsvcSessionInfo** registry key
	- Located in the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity` hive

Check logged on users (active sessions) on all domain controllers
```powershell
Get-DomainController | Get-NetSession
```

Enumerate what ACEs are applied to user E.g., stepbrother
```powershell
Get-ObjectAcl -Identity stepbrother
```
- Access Control Entries (ACE) make up the Access Control List (ACL)
- Each ACE defines whether access to the specific object is allowed or denied.

Enumerate ACLs for group E.g., Sales Department
```powershell
Get-ObjectAcl -Identity "Sales Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

Convert SID into name
```powershell
Convert-SidToName S-1-5-21-1970278769-659589069-1781438869-1104
```

Converting multiple SIDs into name
```powershell
"S-1-5-21-1970278769-659589069-1781438869-512","S-1-5-21-1970278769-659589069-1781438869-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1970278769-659589069-1781438869-519" | Convert-SidToName
```

Find the shares in the domain
```powershell
Find-DomainShare
```

Find domain shares available to us
```powershell
Find-DomainShare -CheckShareAccess
```

Find object ACLs in the current (or specified) domain with modification rights set to non-built in objects.
```powershell
Find-InterestingDomainAcl
```

Change user password E.g., salesman
```powershell
$UserPassword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
Set-DomainUserPassword -Identity salesman -AccountPassword $UserPassword
```
- Needs GenericAll access on user to change password

#Active_Directory_Authentication 

Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes
```
Invoke-Kerberoast
```

# References
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview