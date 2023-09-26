> A Python script that provides the ability to perform: 
> 	Check all NS Records for Zone Transfers. 
> 	Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT)
> 	Perform common SRV Record Enumeration. 
> 	Top Level Domain (TLD) Expansion.

# Usage

#DNS_Enumeration #DNS

Using `dnsrecon` to perform a standard scan
```bash
dnsrecon -d megahentai.com -t std
```

Brute forcing hostnames using `dnsrecon`
```bash
dnsrecon -d megahentai.com -D ~/list.txt -t brt
```

Using `dnsrecon` to perform a zone transfer
```bash
dnsrecon -d megahentai.com -t axfr
```