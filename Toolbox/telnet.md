>  A client/server application protocol that provides access to virtual terminals of remote systems on local area networks or the Internet


#SMTP_Enumeration #SMTP

## dism
> A command-line tool that is used to service Windows images

Installing the Telnet client
```powershell
dism /online /Enable-Feature /FeatureName:TelnetClient
```

## telnet
>  A client/server application protocol that provides access to virtual terminals of remote systems on local area networks or the Internet

Interacting with the SMTP service via `telnet` on Windows
```cmd
telnet 192.168.123.69 25
```

