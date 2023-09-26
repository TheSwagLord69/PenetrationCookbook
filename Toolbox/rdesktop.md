> An open source client for Windows NT/2000 Terminal Server and Windows Server 2003/2008. Capable of natively speaking its Remote Desktop Protocol (RDP) in order to present the user’s Windows desktop. Unlike Citrix ICA, no server extensions are required.


#RDP #Remote_Access

Using rdesktop
```bash
rdesktop -u hentaiuser 192.168.123.169
```

Using rdesktop and share a drive
```bash
rdesktop -u hentaiuser -p hentaipassword 192.168.69.169:3389 -r sound:local -r disk:sharename=/tmp
```