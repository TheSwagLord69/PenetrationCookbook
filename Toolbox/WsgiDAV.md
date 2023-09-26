> A WebDAV server for sharing files and other resources over the web. It is based on the WSGI interface.


#File_Sharing #Client_Side 

Installing pip3 and WsgiDAV
```bash
pip3 install wsgidav
```

Serving WsgiDAV on port 80 with anonymous access settings
```bash
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```