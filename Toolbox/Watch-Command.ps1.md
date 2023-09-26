> This PowerShell module contains a `Watch-Command` cmdlet that can be used to repeatedly run a PowerShell command or scriptblock to return output when it has changed.


#Windows_Enumeration 

# Download

Download
```
https://github.com/markwragg/PowerShell-Watch/blob/master/Watch/Public/Watch-Command.ps1
```

# Usage

Import `Watch-Command.ps1`
```powershell
. .\Watch-Command.ps1
```

Runs Get-Process and returns any differences in the resultant data continuously
```
Get-Process | Watch-Command -Verbose -Diff -Cont -Seconds 1
```

Runs Get-Service and returns any differences in the resultant data continuously
```
Get-Service | Watch-Command -Diff -Cont
```

