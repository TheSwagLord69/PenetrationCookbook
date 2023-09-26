> This program allows you to dump the traffic on a network. 
> tcpdump is able to examine IPv4, ICMPv4, IPv6, ICMPv6, UDP, TCP, SNMP, AFS BGP, RIP, PIM, DVMRP, IGMP, SMB, OSPF, NFS and many other packet types.


#Linux_Enumeration #Web_Application 

Using `tcpdump`
```bash
sudo tcpdump
```

Capture traffic in and out of the loopback interface, dump its content in ASCII and grep for "pass"
```bash
sudo tcpdump -i lo -A | grep "pass"
```

Starting `tcpdump` to listen for ping through the `tun0` interface.
```
sudo tcpdump icmp -i tun0
```

Starting `tcpdump` to listen on TCP/8080 through the `tun0` interface.
```bash
sudo tcpdump -nvvvXi tun0 tcp port 8080
```
- `tcp port 8080`
	- Start the capture filtering `tcp port 8080` to isolate the port 8080 traffic

Starting `tcpdump` to listen on UDP/53 though the `ens192` interface for DNS packets
```bash
sudo tcpdump -i ens192 udp port 53
```
- `udp port 53`
	- Capture filter for DNS packets on UDP/53

Starting `tcpdump` to listen on TCP and UDP on all interfaces
```bash
tcpdump -i any -vvv
```