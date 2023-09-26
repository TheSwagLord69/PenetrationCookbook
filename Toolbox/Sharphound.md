> SharpHound is the official data collector for BloodHound. It is written in C# and uses native Windows API functions and LDAP namespace functions to collect data from domain controllers and domain-joined Windows systems.
> 
> SharpHound is available in a few different formats. We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script


#Active_Directory_Enumeration 

[https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors "https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors")

# Usage

Using SharpHound binary to collect domain data
```
./SharpHound.exe --CollectionMethods All
```

Importing the `SharpHound.ps1` script to memory
```
Import-Module .\Sharphound.ps1
```

View SharpHound options
```
Get-Help Invoke-BloodHound
```

Running SharpHound to collect domain data
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\salesman\Desktop\ -OutputPrefix "hentai audit"
```
- By default, SharpHound will gather the data in JSON files and automatically zip them for us
- Analyze data (.zip file) using Neo4j and Bloodhound