> A tool used to query Domain Name System (DNS) servers and retrieve information about a specific domain or IP address.


#DNS_Enumeration

Using `nslookup` to make a DNS request and perform a simple host enumeration
```bash
nslookup mail.megahentai.com
```

Using `nslookup` to perform a more specific query
```bash
nslookup -type=TXT info.megahentai.com 192.168.69.123
```

Using `nslookup` to request for TXT records
```bash
nslookup -type=txt www.megahentai.com
```