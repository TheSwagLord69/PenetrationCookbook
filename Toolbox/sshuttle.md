> Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.


#Port_Forwarding #SSH #SSH_Tunneling #Tunneling

After using socat to locally forward port 2222 on 192.168.50.63 to port 22 on 10.4.50.215.
Run sshuttle from our Kali machine, pointing to the forward port on 192.168.50.63:2222
```bash
sshuttle -r waifulover@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```
- `-r waifulover@192.168.50.63:2222`
	- specify the SSH connection string we want to use
- `10.4.50.0/24 172.16.50.0/24`
	- specify the subnets that we want to tunnel through this connection
		- 10.4.50.0/24
		- 172.16.50.0/24
- Any traffic intended for the speciffied subnets will be forwarded as if you were waifulover on 192.168.50.63