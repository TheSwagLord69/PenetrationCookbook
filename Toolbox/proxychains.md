> A tool that allows you to route network traffic through a proxy server or a chain of proxy servers. It can be used to enhance privacy, bypass network restrictions, or access resources that are not directly accessible from your local machine.


#Port_Forwarding 

Edit Proxychains configuration file stored by default at /etc/proxychains4.conf
```bash
sudo nano /etc/proxychains4.conf
```
```/etc/proxychains4.conf
socks5  192.168.169.69 9999
```

smbclient connecting to WEEBSHARES through the SOCKS proxy using Proxychains.
```bash
proxychains smbclient -L //172.16.69.123/ -U weeb_admin --password=Weebster1234
```

nmap-over-Proxychains
```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.69.169
```

Crackmapexec over Proxychains
```bash
proxychains -q /home/kali/.local/pipx/venvs/crackmapexec/bin/crackmapexec smb 172.16.169.69-169 172.16.169.254 -u salesman -d hentai.com -p "fgtasstfvck#aQ" --shares
```