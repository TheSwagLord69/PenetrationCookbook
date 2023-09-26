> John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack through brute force) passwords, and even automatically mail users warning them about it, if it is desired.


#Hash #Password_Attacks

# Rules

Add a name for the rules and append them to the `/etc/john/john.conf` configuration file.
```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

Appending the named rules to the `JtR` configuration file
```bash
sudo sh -c 'cat /home/kali/Downloads/ssh.rule >> /etc/john/john.conf'
```

# Hash Cracking

Cracking the hash with `JtR`
```bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

#KeePass 

Format the KeePass database for `hashcat`
```
keepass2john Database.kdbx > keepass.hash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
```
- Keepass2John can be used to extract password hashes from a KeePass database file and convert them into a format that can be used with John the Ripper.

#SSH

Cracking the passphrase of the SSH private key
```
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```
- Transforms RSA/DSA/EC/OPENSSH private keys to john format for later cracking using JtR
	- id_rsa
	- id_ecdsa
	- id_ecdsa_sk
	- id_ed25519
	- id_ed25519_sk
	- id_dsa

#zip

Cracking the passphrase of password protected zip file
```
zip2john 2dwaifuimages.zip > 2dwaifuimages.hash
john --wordlist=/usr/share/wordlists/rockyou.txt 2dwaifuimages.hash
```