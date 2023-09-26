> An advanced CPU/GPU-based password recovery utility supporting seven unique modes of attack for over 100 optimized hashing algorithms.


#Hash #Password_Attacks

# Hash Examples

View the example hashes
```
https://hashcat.net/wiki/doku.php?id=example_hashes
```

# Hash Identification

Using `hashcat` identify
```bash
hashcat --identify $2y$10$XrrpX8RDwtzPuTl6IFvBcOqJ8kO2px2xsh17f60GZsBKLeszsQTBC
```

Using `hashcat` to finding the right mode
```bash
hashcat --help | grep -i "KeePass"
```

# Rules

`hashcat` rules
```bash
https://hashcat.net/wiki/doku.php?id=rule_based_attack
```

Creating a rule for `hashcat` at `demo1.rule`
```
$1 c $!
```

Using `hashcat` to test the rules
```bash
hashcat -r demo1.rule --stdout passwords.txt
```

Cracking a MD5 Hash with `hashcat` and a mutated `rockyou.txt` wordlist
```bash
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```

Listing of `hashcat`'s rule files
```bash
ls -la /usr/share/hashcat/rules/
```

# Hash Cracking

Using `hashcat` to crack WordPress (MD5) hash
```bash
hashcat -m 400 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack KeePass database hash
```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
- Format the KeePass database
	- `keepass2john Database.kdbx > keepass.hash`

Using `hashcat` to crack Windows NTLM hashes
```bash
hashcat -m 1000 salesmanhash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack Net-NTLMv2 hash
```bash
hashcat -m 5600 salesman.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack Atlassian (PBKDF2-HMAC-SHA1) hash (postgreSQL PKCS5S2)
```bash
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack AS-REP hash (AS-REP Roasting)
```bash
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack TGS-REP hash (Kerberoasting)
```bash
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using `hashcat` to crack HMAC-SHA1 (known_hosts)
```bash
hashcat -m 160 --quiet --hex-salt converted_known_hosts -a 3 ipv4_hcmask.txt 
```

Using `hashcat` to crack SHA256CRYPT hash
```bash
sudo hashcat -m 7400 sha256crypthashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

# Cracked Hashes

View hashes cracked by `hashcat`
```
cat /home/kali/.local/share/hashcat/hashcat.potfile
```

Cracked NTLM hash may give $HEX as output
```
$HEX[61e1]
```
- Convert the string in the brackets to ascii