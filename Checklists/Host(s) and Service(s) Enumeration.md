
- [ ] Full network scan using `autorecon` on your Kali Machine
```
sudo env "PATH=$PATH" autorecon 192.168.yyy.yyy
```

- [ ] Full `nmap` TCP scan on your Kali Machine
```
sudo nmap -p- -sT -A 192.168.yyy.yyy -oG tcp_nmap_host.txt -v
```

- [ ] Full `nmap` UDP scan on your Kali Machine
```
sudo nmap -p- -sU -A 192.168.yyy.yyy udp_nmap_host.txt -v
```

- [ ] Service vulnerability `nmap` scan on your Kali Machine
```
nmap -sV --script vuln 192.168.yyy.yyy
```

- [ ] Search exploits for found technologies and versions on your Kali Machine
```
searchsploit Apache 2.4
```

- [ ] Manually connect to services that are unidentified or "weird" from your Kali Machine
```
nc -nv 192.168.yyy.yyy 3003
help
?
/
```
```
telnet 192.168.yyy.yyy 3003
help
?
/
```