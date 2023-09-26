> Tool used to brute-force: 
> - URIs (directories and files) in web sites, 
> - DNS subdomains (with wildcard support), 
> - Virtual Host names on target web servers, 
> - Open Amazon S3 buckets, 
> - Open Google Cloud buckets and TFTP servers.


#Web_Application 

# Usage

Running `gobuster`
```bash
gobuster dir -u 192.168.169.123 -w /usr/share/wordlists/dirb/common.txt -t 5
```

# Pattern

`gobuster` pattern
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

Bruteforcing API Paths using pattern
```bash
gobuster dir -u http://192.168.169.123:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
```
