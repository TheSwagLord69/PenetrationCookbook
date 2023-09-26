
- [ ] `nmap` script scan on your Kali Machine
```
nmap -sT -A -p 135,139 192.168.yyy.yyy
```

- [ ] Scan for open NETBIOS nameservers on your Kali Machine
```
sudo nbtscan -r 192.168.yyy.yyy
```

- [ ] Enumerate using all methods on your Kali Machine
```
enum4linux -a 192.168.yyy.yyy
```

- [ ] List shares with no credentials on your Kali Machine
```
smbclient --no-pass -L //192.168.yyy.yyy
```

- [ ] List shares with credentials to list shares on your Kali Machine
```
smbclient -p 4455 -L //192.168.yyy.yyy/ -U sales_admin --password=Sussybaka1234
```

- [ ] Recursively list files in specific share with credentials on your Kali Machine
```
proxychains smbclient -p 445 //192.168.yyy.yyy/NETLOGON -U hentai_svc --password=Hardness1 -c 'recurse;ls'
```

- [ ] Login with a NTLM hash with `smbclient` from your Kali Machine
```
smbclient \\\\192.168.yyy.yyy\\nastystuff -U Administrator --pw-nt-hash b42057ba2eb66ea7c0d1350de3957a8b
```
