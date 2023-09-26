> Powershell package


#Windows_Enumeration 

# Download

Possibly downloaded at
```
https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/NtObjectManager/NtObjectManager.psd1
```

# Usage

Using `NtObjectManager`
```
powershell -ep bypass
Import-Module NtObjectManager
```

Display the integrity level of the current process by retrieving and reviewing the assigned access token
```
Get-NtTokenIntegrityLevel
```