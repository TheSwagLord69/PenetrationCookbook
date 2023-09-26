> The File Transfer Protocol is a standard communication protocol used for the transfer of computer files from a server to a client on a computer network.


#FTP 
# Usage

Login using anonymous credentials
```
ftp 192.168.101.69
anonymous
anonymous@domain.com
```

Turn off passive mode, set binary mode and upload file
```
passive
binary
put putty.exe
```

Download file
```
get flag.txt
```

Download all files in current directory
```
mget *
```