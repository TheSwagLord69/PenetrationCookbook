> A multi-threaded network reconnaissance tool which performs automated enumeration of services.


# Download

Github Repo
```
https://github.com/Tib3rius/AutoRecon
```

Installing `autorecon`
```bash
sudo apt install python3
sudo apt install python3-pip
sudo apt update
sudo apt install seclists
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
sudo apt install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath --force
nano ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
nano ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"
pipx install git+https://github.com/Tib3rius/AutoRecon.git
```

# Usage

#Port_Scanning 

Using `autorecon`
```bash
autorecon 192.168.69.169
```

Using `autorecon` with `sudo`
```bash
sudo env "PATH=$PATH" autorecon [OPTIONS]
sudo $(which autorecon) [OPTIONS]
```
- Allows UDP scanning

Using `autorecon` with `proxychains`
```bash
sudo proxychains -q $(which autorecon) 192.168.69.169 192.168.69.170
```