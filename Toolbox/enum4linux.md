> Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from [www.bindview.com](https://www.bindview.com/).


# Usage

#SMB_Enumeration #SMB

Perform all checks
```bash
enum4linux -a 192.168.169.247
```

Show SMB users
```bash
enum4linux -U 192.168.169.248
```

Show SMB shares
```bash
enum4linux -S 192.168.169.249
```

Show OS Information
```bash
enum4linux -o 192.168.169.250
```

Login with credentials
```bash
enum4linux -u user_name -p pass_word 192.168.169.251
```