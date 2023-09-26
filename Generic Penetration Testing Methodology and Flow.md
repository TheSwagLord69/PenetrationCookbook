> A General Penetration Testing Methodology and Flow


#General 

# Stuck?
- Web application
	- Have you tried to dirbust recursively or with a pattern?
	- Have you searched for exploits on all information presented? E.g., Version, title.
- Initial access / Lateral movement
	- Have you ran a FULL portscan?
	- Have you start a tunnel/port forward?
	- Have you sprayed all your credentials on all services?
		- Dont trust output from CME
	- Have you tried variations of usernames?
		- E.g., jack, Jack, JACK
	- Have you tried username as password
		- E.g., alice:alice
	- Have you looted everything from the previous machine?
		- Console history
		- NTLM hashes
		- All possible files that may contain credentials
	- Have you tried specifying the port, even if its the default port?
- Privilege escalation
	- Have you tried using different users to do the same thing?
	- Have you tried using different services to do the same thing?
	- Have you enumerated all the files?
	- Have you tried using a webshell?
	- Have you tried hashes as password string?
	- Have you actually read the exploit and patched it for your scenario?
- Reverse shell / Exploits
	- Have you removed all unnecessary spaces and line breaks from exploit?
	- Have you tried lowering mtu?
		- `sudo ifconfig tun0 mtu 1250`
		- Try to get MTU slightly above payload size
	- Have you tried using nc from usr/bin/, /.local/bin or busybox
	- Have you encoded your payload
	- Have you changed the names of your payload?
		- It might be using the previous payload instead of the new payload
---
# Common Services and Ports
- **UDP**
	- TFTP
		- 69
	- SNMP
		- 161
- **TCP**
	- FTP
		- 21
	- SSH
		- 22
	- SMTP
		- 25
		- 587
	- POP3
		- 110
	- IMAP
		- 143
	- HTTP
		- 80
	- HTTPS
		- 443
	- SMB
		- 139
		- 445
	- MySQL
		- 3306 
	- RDP
		- 3389
	- WinRM
		- 5985 (HTTP)
		- 5986 (HTTPS)

---
# Port Forwarding

1. **Local Static Port Forward**
	1. SSH
		1. Navigate to machine for the port forward to be set up
		2. Set up local port forward
			1. `ssh -N -L 0.0.0.0:4455:172.16.50.217:445 admin@10.4.50.215`
		3. Probe the forward port (4455) of the machine from our Kali
	2. Socat
		1. Navigate to machine for the port forward to be set up
		2. Set up local port forward
			1. `socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432`
		3. Probe the forward port (2345) of the machine from our Kali
	3. Netsh
		1. Navigate to the windows machine for the port forward to be set up
		2. Add portproxy rule
			1. `netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`
		3. Add firewall rule
			1. `netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`
		4. Probe the forward port (2222) of the machine from our Kali
2. **Local Dynamic Port Forward**
	1. SSH
		1. Navigate to machine for the port forward to be set up
		2. Set up local dynamic port forward with sock5 proxy
			1. `ssh -N -D 0.0.0.0:9999 admin@10.4.50.215`
		3. Edit proxychains configuration file our Kali machine
			1. `sudo nano /etc/proxychains4.conf`
			2. `socks5 192.168.202.63 9999`
		4. Use proxychains on internal IP addresses
3. **Remote Static Port Forward**
	1. SSH
		1. Start SSH server on our Kali machine
			1. `sudo systemctl start ssh`
		2. Navigate to machine for the port forward to be set up
		3. Set up remote static port forward back to our Kali machine
			1. `ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4`
		4. Probe the forward port (2345) on the loopback interface of our own Kali machine
4. **Remote Dynamic Port Forward**
	1. SSH
		1. Start SSH server on our Kali machine
			1. `sudo systemctl start ssh`
		2. Navigate to machine for the port forward to be set up
		3. Set up remote dynamic port forward
			1. `ssh -N -R 9998 kali@192.168.118.4`
		4. Edit proxychains configuration file on our Kali machine
			1. `sudo nano /etc/proxychains4.conf`
			2. `socks5 127.0.0.1 9998`
		5. Use proxychains to run tools on internal IP addresses
			1. `proxychains curl 127.0.0.1:8000`
---
# Tunneling

1. **DNS**
	1. `dnscat2`
		1. Start the dnscat2 server
			1. `dnscat2-server hhentai.corp`
		2. Run dnscat2 client
			1. `./dnscat hhentai.corp`
2. **HTTP**
	1. `Chisel`
		1. Start Chisel server (reverse proxy)
			1. `chisel server --port 8080 --reverse`
		2. Start Chisel client
			1. `.\chisel.exe client 192.168.100.5:8080 R:socks`
3. **SSH**
	1. sshuttle
		1. Set up a local port forward on the machine
		2. Run sshuttle from our Kali machine
			1. `sshuttle -r db_admin@192.168.133.32:2222 10.4.202.0/24 172.16.202.0/24`
		3. Run tools on internal IP addresses without any explicit forwarding
	2. plink
		1. Start SSH server on our Kali machine
		2. Navigate to Windows machine
		3. Making an SSH connection to our Kali machine
			1. `plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.201.4`
---
# Vulnerability Scanning

1. **Host discovery**
	1. `nmap`
2. **Port scanning (Full scan)**
	1. `nmap`
	2. `autorecon`
	3. `rustscan`
3. **Detect OS, Services, Versions**
	1. `whatweb`
	2. `nmap NSE`
	3. `Nessus`
4. **Enumerate services**
	1. SMB Enumeration
		1. `nmap`
		2. `nbtscan`
		3. `net view`
		4. `smbclient`
	2. SMTP Enumeration
		1. `nc`
		2. `telnet`
		3. `python`
		4. `PowerShell`
	3. SNMP Enumeration
		1. `nmap`
		2. `onesixtyone`
		3. `snmpwalk`
5. **Match results to a vulnerability database**
	1. `searchsploit`
6. **Fix exploits and use**
---
# Web Application Attacks

1. **Fingerprint Web Application**
	1. `nmap`
	2. `wappalyzer`
2. **Brute Force Directory** 
	1. Directory wordlists
	2. Gobuster pattern
	3. feroxbuster
3. **Enumerate Web Application**
	1. robots.txt
	2. Debugger tool
	3. Inspector tool
	4. Network tool
4. **Check for Directory Traversal Vulnerabilities**
	4. Absolute Paths
	5. Relative Paths
	6. Encoding Special Characters
5. **Check for File Inclusion Vulnerabilities**
	1. Local File Inclusion (LFI)
	2. Log Poisoning
	3. PHP Wrappers
	4. Remote File Inclusion (RFI)
6. **Check for use of Executable Files**
	1. Webshells
7. **Check for use of Non-Executable Files**
8. **Check for OS Command Injection**
---
# Attacking Logins

1. **Brute force service login** (E.g., SSH, RDP, FTP, HTTP POST, HTTP GET)
	1. `hydra`
	2. `Burp Suite Intruder`
2. **Password Spray AD users**
	1. `crackmapexec`
---
# Windows Privilege Escalation

1. **Automated Enumeration**
	1. `winPEAS.exe`
	2. `Seatbelt.exe`
	3. `PowerUp.ps1`
2. **View command history**
	1. Current session
		1. `Get-History`
	2. History file
		1. `(Get-PSReadlineOption).HistorySavePath`
3. **Enumerate User Privileges and Groups**
	1. Current user
		1. `whoami /all`
			1. `whoami /priv`
			2. `whoami /groups`
	2. List local users
		1. `Get-LocalUser`
		2. `net user`
	3. Local groups
		1. `Get-LocalGroup`
		2. `net user alex`
		3. `Get-LocalGroupMember Administrators`
4. **Enumerate files for sensitive information**
	1. Go through files in drives, Desktop, Documents, etc.
	2. Show permissions of files
	3. Show permissions of directories
5. **Enumerate running operating system and architecture**
	1. `systeminfo`
6. **Enumerate running processes**
	1. `Get-Process | Select-Object Path`
	2. `procexp64.exe`
	3. `Get-Service | Watch-Command -Diff -Cont`
7. **Enumerate services**
	1.  Installed Windows services
		1. `Get-Service`
8. **Abuse privileges**
	1. `SeImpersonatePrivilege`
		1. Printspoofer
		2. Potatoes
			1. `GodPotato`
9. **Check for Service Binary Hijacking**
	1. List installed services
		1. `Get-Service`
		2. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName`
	2. List running services
		1. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
	3. Show permissions of file/directory
		1. `icacls "C:\xampp\apache\bin\httpd.exe"`
10. **Check for Service DLL Hijacking**
	1. Unquoted Service Paths
		1.  `Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*"} | Where-Object {$_.PathName -notlike "*""*"} | Select-Object Name, PathName`
	2. Show the PATH environment variable to view the Windows DLL search order
		1. `$env:path`
11. **Check for Scheduled Tasks**
	1. `schtasks /query /fo LIST /v`
12. **Dump password hashes**
	1. `mimikatz`
13. **Check for Exploits**
	1. `searchsploit`
	2. lolbas-project.github.io
	3. wadcoms.github.io
14. **Enumerate active network connections**
	1. TCP/IP configuration
		1. `ipconfig /all`
	2. Active network connections
		1. `netstat -ano`
	3. Routing table
		1. `route print`
15. **Move laterally**
---
# Linux Privilege Escalation

1. **Automated Enumeration**
	1. `linPEAS`
2. **Enumerate users**
	1. Current user 
		1. User information
			1. `id`
		2. Abusing Sudo
			1. `sudo -l`
		3. Environment Variables
			1. `env`
		4. View dotfiles
			1. `.bash_profile`
			2. `.bashrc`
	2. List users on the machine
		2. `cat /etc/passwd`
3. **Enumerate running operating system and architecture**
	1. `hostname`
	2. `uname -a`
	3. `cat /etc/issue`
	4. `cat /etc/os-release`
	5. `cat /proc/version`
	6. `lsb_release -a`
	7. `arch`
4. **Enumerate network information**
	1. TCP/IP configuration
		1. `ip a`
	2. Active network connections
		1. `netstat`
	3. Routing table
		1. `route`
	4. Password Sniffing
		1. `tcpdump -i any -vvv`
5. **Enumerate running processes**
	1. `watch 'ps -aux'`
	2. `./pspy64`
6. **Inspecting file permissions and users ownership**
	1. SUID files
		1. `find / -perm -u=s -type f 2>/dev/null`
	2. Cron Jobs
		1. `ls -lah /etc/cron*`
	3. Capabilities
		1. `/usr/sbin/getcap -r / 2>/dev/null`
	4. Log files
		1. `cat /var/log/`
	5. Writable files
		1. `find / -writable -type d 2>/dev/null`
		2. `find / -writable -type f 2>/dev/null`
	6. Password Files
		1. Editing `/etc/passwd`
	7. Package files
		1. `dpkg -l`
7. **List all available drives**
	1. `lsblk`
8. **List loaded drivers**
	1. `lsmod`
9. **Check for exploits**
	1. `searchspolit`
	2. gtfobins.github.io
---
# Dumping Hashes

1. **Obtain elevated privileges**
2. **Dump password hashes**
	1. `mimikatz`
---
# Cracking Hashes

1. **Determine hash type**
	1. `hash-identifier`
	2. `hashID`
2. **Mutate wordlists**
3. **Create rule functions**
4. **Set correct mode and crack hash**
	1. `hashcat`
	2. `john`
---
# Active Directory

## Active Directory Enumeration
1. **Automated Enumeration**
	1. `adPEAS.ps1`
	2. `PowerView.ps1`
	3. `SharpHound`
2. **Domain information**
	1. `Get-NetDomain`
3. **Domain users**
	1. All domain users
		1. `net user /domain`
	2. User's groups
		1. `net user hentaiadmin /domain`
	3. User permissions
		1. `Get-ObjectAcl -Identity salesman`
	4. Current User
		1. `Find-LocalAdminAccess`
	5. Logged in users
		1. `Get-NetSession -ComputerName filez69 -Verbose`
		2. `.\PsLoggedon.exe \\files04`
	6. SPN accounts
		1. `setspn -L iis_service`
		2. `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
	7. Object permissions
4. **Domain groups** 
	1. Show all groups
		1. `net group /domain`
		2. `Get-NetGroup | select cn`
	2. Show group members
		1. `net group "Sales Department" /domain`
	3. Show group permissions
		1. `Get-ObjectAcl -Identity "Hentai Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
5. **Domain machines**
	1. All domain computers 
		1. `Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion`
	2. Domain Controllers
		1. `Get-NetDomainController`
		2. `nltest /dclist:hentaii.com`
	3. Resolve host
		1. `nslookup.exe weebs02.hentai.com`
		2. `Resolve-IPAddress -ComputerName weebs01`
6. **Domain shares** 
	1. Show all shares
		1. `Find-DomainShare`
	2. Show domain shares available to us
		1. `Find-DomainShare -CheckShareAccess`
	3. Listing contents of the share
		1. `ls \\dc1.hentai.com\sysvol\hentai.com\`
		2. `cat \\dc1.hentai.com\sysvol\hentai.com\Policies\oldpolicy\old-policy-backup.xml`
7. **Misconfigured Object ACL**
	1. `Find-InterestingDomainAcl`
8. **Password Policies**
	1. `net accounts /domain`
	2. `Get-ADDefaultDomainPasswordPolicy`

## Active Directory Authentication
1. **Password Attacks on AD Users**
	1. Use LDAP and ADSI to perform a _low and slow_ password attack
		1. `Spray-Passwords.ps1`
	2. Use SMB to spray passwords
		1. `crackmapexec`
	3. Obtain a TGT (Ticket Granting Ticket)
		1. `.\kerbrute_windows_amd64.exe`
2. **AS-REP Roasting**
	1. `impacket-GetNPUsers`
	2. `.\Rubeus.exe`
3. **Kerberoasting**
	1.  `impacket-GetNPUsers`
	2. `.\Rubeus.exe`
4. **Silver tickets**
	1. Forge silver ticket
		1. `.\mimikatz.exe`
			1. NTLM hash of the service account
				1. `.\mimikatz.exe`
			2. Domain SID
				1. `whoami /user`
			3. Target SPN
	2. List Kerberos tickets
		1. `klist`
5. **dcsync (Domain Controller Synchronization)**
	1. `.\mimikatz.exe`
	2. `impacket-secretsdump`

## Active Directory Lateral Movement
1. **Windows Management Instrumentation**
	1. WMI (CIM and DCOM)
		1. `wmic`
		2. `Invoke-CimMethod`
2. **Windows Remote Management**
	1. `winrm`
	2. Powershell Remoting (WinRM)
		1. `New-PSSession`
		2. `Enter-PSSession`
	3. `evil-winrm`
3. **Windows Remote Shell (Remote Shell Protocol)**
	1. WinRS
		1. `winrs`
4. **PsExec**
	1. `PsExec64.exe`
5. **Pass the Hash**
	1. `impacket-wmiexec`
	2. `impacket-psexec`
	3. `evil-winrm`
6. **Overpass the Hash / Pass The Key (PTK)**
	1. `.\mimikatz.exe`
		1. Pass the Hash, run powershell
			1. `sekurlsa::pth`
		2. Generate a TGT by authenticating to a network share
			1. `net use \\files04`
		3. Inject the selected TGS into process memory
			1. `kerberos::ptt`
	2. `.\Rubeus.exe`
7. **Pass the Ticket**
	1. Export Kerberos tickets stored in memory 
		1. `sekurlsa::tickets /export`
	2. Inject selected TGS into process memory
		1. `kerberos::ptt`
	3. Start an interactive session after getting TGS
		1. `.\PsExec.exe \\weebs69 cmd`
8. **DCOM**
	1. `$dcom.Document.ActiveView.ExecuteShellCommand`

## Active Directory Persistence
1. **Golden Ticket**
	1. Extract krbtgt hash
		1. `lsadump::lsa /patch`
	2. Get domain SID
		1. `whoami /user`
	3. Create golden ticket
		1. `kerberos::golden`
2. **Shadow Copies**
	1. Copy NTDS database
	2. Save system hive
		1. `reg.exe`
	3. Extract NTLM hashes and Kerberos keys for every AD user
		1. `impacket-secretsdump`
3. **SAM file**
	1. Copy out SAM
	2. Copy out SYSTEM
	3. Dump Windows 2k/NT/XP password hashes from a SAM file
		1. `samdump2 SYSTEM SAM`

## Glossary of Terms
- TGT
	- Ticket-Granting Ticket
- TGS (Service tickets)
	- Ticket-Granting Service
- AS-REP Roast
	- Get user password hashes that "Do not require Kerberos preauthentication"
- Kerberoast
	- Get service account password hashes
- Pass the Hash
	- Authenticate with password hash without plaintext password
- Over Pass the Hash
	- Get TGT and TGS with password hash
- Pass the Ticket
	- Using an injected user's ticket
- Silver Ticket
	- Forged TGS for a specific service or resource within the AD environment for any users and permissions
- Golden Ticket
	- Forged TGT for the domain's KDC (Key Distribution Center)
---
