> Shellter is a dynamic shellcode injection tool aka dynamic PE infector. It can be used in order to inject shellcode into native Windows applications (currently 32-bit apps only). The shellcode can be something yours or something generated through a framework, such as Metasploit.


#Antivirus_evasion 

Installing `shellter` in Kali Linux
```bash
apt-cache search shellter
sudo apt install shellter
```

Installing `wine` in Kali Linux
```bash
sudo apt install wine
```
```bash
dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32
```
```bash
apt-get install wine32:i386
```

Remove old `~/.wine` folder
```bash
rm -r ~/.wine
```