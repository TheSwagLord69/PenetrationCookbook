> One of the most popular, versatile, and robust port scanners available. 
> It has been actively developed for over two decades and offers numerous features beyond port scanning.


#Port_Scanning

Configuring our `iptables` rules for the scan
```bash
sudo iptables -I INPUT 1 -s 192.168.69.123 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 192.168.69.123 -j ACCEPT
sudo iptables -Z
```

Scanning an IP for the 1000 most popular TCP ports
```bash
nmap 192.168.69.123
```

Using `iptables` to monitor `nmap` traffic for a port scan
```bash
sudo iptables -vn -L
```

Using `nmap` to perform a SYN scan
```bash
sudo nmap -sS 192.168.69.123
```

Using `nmap` to perform a TCP connect scan
```bash
nmap -sT 192.168.69.123
```

Using `nmap` to perform a UDP scan
```bash
sudo nmap -sU 192.168.69.123
```

Using `nmap` to perform a combined UDP and SYN scan
```bash
sudo nmap -sU -sS 192.168.69.123
```

Using `nmap` to perform a network sweep
```bash
nmap -sn 192.168.69.1-254
```

Using `nmap` to perform a network sweep and using `grep` to find live hosts
```bash
nmap -v -sn 192.168.69.1-254 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2
```

Using `nmap` to scan for web servers using port 80 and using `grep` to find live hosts
```bash
nmap -p 80 192.168.69.1-254 -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2
```

Using `nmap` to perform a top twenty port scan, saving the output in greppable format
```bash
nmap -sT -A --top-ports=20 192.168.69.1-254 -oG top-port-sweep.txt
```

The `nmap-services` file showing the open frequency of TCP port 80
```bash
cat /usr/share/nmap/nmap-services
```

Using `nmap` for OS fingerprinting
```bash
sudo nmap -O 192.168.69.123 --osscan-guess
```

Using `nmap` for banner grabbing and/or service enumeration
```bash
nmap -sT -A 192.168.69.123
```

Using `nmap`'s scripting engine (NSE) for OS fingerprinting
```bash
nmap --script http-headers 192.168.69.123
```

Showing the `nmap` NSE scripts
```bash
cat /usr/share/nmap/scripts
```

Using the `--script-help` option to view more information about a script
```bash
nmap --script-help http-headers
```

#SMTP_Enumeration 

Enumerate SMTP commands
```
nmap --script smtp-commands 192.168.69.123
```

Enumerate the users on a SMTP server using EXPN, VRFY, RCPT
```
nmap -script smtp-enum-users.nse 192.168.69.123
```

Check for SMTP Open Relay
```
nmap --script smtp-open-relay 192.168.69.123 -v
```

#SMB_Enumeration

Using `nmap` to scan for the NetBIOS service
```bash
nmap -v -p 139,445 -oG smb.txt 192.168.69.1-254
cat smb.txt
```

Finding various nmap SMB NSE scripts
```bash
ls -1 /usr/share/nmap/scripts/smb*
```

Using the `nmap` scripting engine to perform OS discovery
```bash
nmap -v -p 139,445 --script smb-os-discovery 192.168.69.123
```

Enumerate SMB
```bash
sudo nmap -Pn -sU -sS --script smb-enum-users.nse -p U:137,T:139 192.168.69.123
```

#SNMP_Enumeration

Using `nmap` to perform a SNMP scan
```bash
sudo nmap -sU --open -p 161 192.168.69.1-254 -oG open-snmp.txt
```

#Vulnerability_Scanning 

Listing NSE scripts containing the word "Exploits"
```bash
grep Exploits /usr/share/nmap/scripts/*.nse
```

The Nmap script database
```bash
cd /usr/share/nmap/scripts/
cat script.db  | grep "\"vuln\""
```

Using NSE's "vuln" category scripts
```bash
sudo nmap -sV -p 443 --script "vuln" 192.168.69.123
```

Copy the NSE Script and update the script.db database
```bash
sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb
```

Using CVE-2021-41773 NSE Script
```bash
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.69.123
```

#Web_Application

Running `nmap` scan to discover web server version
```bash
sudo nmap -p80  -sV 192.168.69.123
```

Running `nmap` NSE http enumeration script against the target
```bash
sudo nmap -p80 --script=http-enum 192.168.69.123
```

