> This tool is designed to dump Windows 2k/NT/XP password hashes from a SAM file, using the syskey bootkey from the system hive.

> **THIS DOESNT REALLY WORK**
> Use pwdump.py instead


#Hash #Password_Attacks #NTLM_Hash 

Files usually found in
```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
```

Get `SYSTEM` and `SAM` files using `reg`
```
reg save hklm\system SYSTEM
reg save hklm\sam SAM
reg save hklm\security SECURITY
```

Usage
```
samdump2 SYSTEM SAM
```