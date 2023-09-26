> A client that can 'talk' to an SMB/CIFS server. It offers an interface similar to that of the ftp program


#SMB_Enumeration #SMB

Using `smbclient` connect
```bash
smbclient //192.168.123.69/sussystuff
```

Using `smbclient` connect without credentials
```bash
smbclient //192.168.123.169/Users --no-pass
```

Listing SMB shares
```bash
smbclient -p 4455 -L //192.168.69.123/ -U sales_admin --password=Wowsale1234
```
```bash
proxychains smbclient -p 445 -L //172.16.169.69/ -U hentai/madlad --password=Dogdance1!
```

Listing SMB shares with no credentials
```bash
smbclient --no-pass -L //192.168.123.169
```

Recursively list files in the share
```bash
smbclient //192.168.123.169/Users --no-pass -c 'recurse;ls'
```

Accessing SMB share
```bash
smbclient -p 4455 //192.168.69.123/scripts -U sales_admin --password=Wowsale1234
```
```bash
proxychains smbclient -p 445 //172.21.69.123/scripts -U hentai/madlad --password=Dogdance1!
```

Uploading file to SMB share E.g., Library file
```bash
smbclient //192.168.69.123/share -c 'put config.Library-ms'
```

Download file from the SMB share
```
get somefile.ps1
```

#Password_Attacks 

Using `smbclient` to pass the NTLM hash
```bash
smbclient \\\\192.168.69.123\\nastystuff -U Administrator --pw-nt-hash 6bf0f274e51ea8377a2960a6ef61be69
```

