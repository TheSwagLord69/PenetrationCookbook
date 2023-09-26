> `feroxbuster` is a tool designed to perform [Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing).
> 
> Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker.
> 
> `feroxbuster` uses brute force combined with a wordlist to search for unlinked content in target directories. These resources may store sensitive information about web applications and operational systems, such as source code, credentials, internal network addressing, etc...
> 
> This attack is also known as Predictable Resource Location, File Enumeration, Directory Enumeration, and Resource Enumeration.


#Web_Application

# Download

Installation
```
sudo apt update && sudo apt install -y feroxbuster
```

# Usage

Usage with default word list
```
feroxbuster -u http://192.168.123.111:80
```

Usage with specific word list
```
feroxbuster -u http://192.168.123.111:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt --quiet
```

Adding common file types to each URL
```
feroxbuster -u http://192.168.123.111:80 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -x pdf,js,html,php,txt,ini,config,json,docx,doc,xls,xlsx,xlsm,zip,log,git --quiet -o ferox_out.txt
```

References:
https://pentesttools.net/feroxbuster-recursive-content-discovery-tool-written-in-rust/
https://medium.com/@cuncis/discover-hidden-directories-and-files-with-feroxbuster-the-ultimate-web-enumeration-tool-cheat-cb55b033baa9