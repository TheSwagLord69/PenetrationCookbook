> A script that search for possible paths to escalate privileges on Windows hosts.


#Windows_Enumeration #Windows_Privilege_Escalation 

Installing Peass-Ng
```bash
sudo apt install peass
```

Location of winPEAS
```bash
cd /usr/share/peass/winpeas/
```

Using winPEAS
```powershell
.\winPEASx64.exe
```

Using winPEAS to do an additional LOLBAS search check
```
.\winPEASx64.exe -lolbas
```