> Free software providing Domain Name System caching, a Dynamic Host Configuration Protocol server, router advertisement and network boot features, intended for small computer networks.


# Usage

#DNS_Server #File_Sharing #DNS

Basic `dnsmasq.conf` configuration for `dnsmasq` server
```
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=hentai.corp
auth-server=hentai.corp
```

`dnsmasq.conf` TXT configuration file for `dnsmasq` server to serve TXT records 
```
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=hentai.corp
auth-server=hentai.corp

# TXT record
txt-record=www.hentai.corp,here's something sussy!
txt-record=www.hentai.corp,here's something else less sussy.
```
```
kali@hentaiauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
dnsmasq: started, version 2.88 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache
```

Starting `dnsmasq` with a configuration
```bash
sudo dnsmasq -C dnsmasq.conf -d
```