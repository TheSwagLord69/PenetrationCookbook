> X11 Remote Desktop Protocol (RDP) client which is part of the FreeRDP project


#RDP #Remote_Access

Using `xfreerdp`
```bash
xfreerdp /u:mikeoxmaul /p:testtest /v:192.168.123.169 /cert:ignore
```

Using `xfreerdp` and share a drive
```bash
xfreerdp /u:mikeoxmaul /p:testtest /v:192.168.123.169 /port:3389 /cert:ignore /drive:tmp,/tmp
```

Using `xfreerdp` with additional tags
```bash
proxychains xfreerdp /u:mikeoxmaul /p:'SizeDoesMatter0k?' /v:192.168.123.169 /port:3389 /d:hentai /cert:ignore /drive:tmp,/tmp /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600
```

Using `xfreerdp` with .rdp file
```bash
xfreerdp some_rdp_filename.rdp /u:hentaisalesman /d:hentaidomain /p:'suSSy^b4k4' /v:192.168.123.169 /port:12345 /cert:ignore /drive:tmp,/tmp
```