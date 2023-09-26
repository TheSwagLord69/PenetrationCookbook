> Simple utility for performing DNS lookups.
> Normally used to convert names to IP addresses and vice versa.


#DNS_Enumeration #DNS

Using `host` to find the A host record for www.megahentai.com
```bash
host www.megahentai.com
```

Using `host` to find the MX records for megahentai.com
```bash
host -t mx megahentai.com
```

Using `host` to find the TXT records for megahentai.com
```bash
host -t txt megahentai.com
```

Using `host` to obtain DNS servers for a given domain name
```bash
host -t ns megahentai.com | cut -d " " -f 4
```

Using `host` to search for a valid host
```bash
host www.megahentai.com
www.megahentai.com has address 150.69.169.69 
```

Using `host` to search for an invalid host
```bash
host idontexist.megahentai.com
Host idontexist.megahentai.com not found: 3(NXDOMAIN)
```

Using Bash scripting to brute force forward DNS name lookups
```bash
for ip in $(cat list.txt); do host $ip.megahentai.com; done
```

Using Bash scripting to brute force reverse DNS names
```bash
for ip in $(seq 200 254); do host 150.69.169.$ip; done | grep -v "not found"
```

Using `host` to illustrate a DNS zone transfer
```bash
host -l megahentai.com ns2.megahentai.com
```

Bash DNS zone transfer script
```bash
#!/bin/bash 
# Simple Zone Transfer Bash Script 
# $1 is the first argument given after the bash script 
# Check if argument was given, if not, print usage 

if [ -z "$1" ]; then 
	echo "[*] Simple Zone transfer script" 
	echo "[*] Usage : $0 " 
	exit 0 
fi 

# if argument was given, identify the DNS servers for the domain 

for server in $(host -t ns $1 | cut -d " " -f4); do 
	# For each of these servers, attempt a zone transfer 
	host -l $1 $server |grep "has address" 
done
```