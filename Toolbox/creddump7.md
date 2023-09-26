> This package contains a Python tool to extract various credentials and secrets from Windows registry hives. It’s based on the creddump program. Many patches and fixes have been applied by Ronnie Flathers.


#Hash #Password_Attacks #Windows_Privilege_Escalation 
# pwdump.py

Files usually found in
```
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
```

Get `SYSTEM` and `SAM` files using `reg`
```powershell
reg save hklm\system system
reg save hklm\sam sam
```

Usage
```bash
/usr/share/creddump7/pwdump.py SYSTEM SAM
```