> PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software. 
> 
> PsExec's most powerful uses include launching interactive command-prompts on remote systems and remote-enabling tools like IpConfig that otherwise do not have the ability to show information about remote systems.
> 
> https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite


# Download

Download
```
https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```

# Usage

#Shell_Access #Remote_Access #Active_Directory_Lateral_Movement #SMB

Start an interactive session on the remote host
```powershell
./PsExec64.exe -i  \\FILES69 -u hentai\salesman -p Sussy123! cmd
```
- Prerequisites:
	- The user authenticating to the target machine must be in Administrators local group
	- _ADMIN$_ share must be available
	- File and Printer Sharing has to be turned on

Start an interactive session after getting TGS
```powershell
.\PsExec.exe \\FILES69 cmd
```