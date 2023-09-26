
- [ ] Transfer the private key file from the Target Machine to your Kali Machine

- [ ] Convert the SSH key into a format that can be used for cracking with ssh2john on your Kali Machine
```
ssh2john id_rsa > ssh.hash
ssh2john id_ecdsa > ecdsa.hash
```

- [ ] Crack the SSH key hash with `JtR` on your Kali Machine
```
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ecdsa.hash
```