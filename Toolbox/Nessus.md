> Vulnerability scanning tool used to identify and assess security vulnerabilities in computer systems, networks, and applications


#Vulnerability_Scanning

# Download

Download the current version of Nessus as a 64bit _.deb_ file for Kali from the Tenable website.
There, we also get the _SHA256_ and _MD5_ checksums for the installer.

Download
```
https://www.tenable.com/downloads/nessus?loginAttempted=true
```

Verifying the checksum
```bash
cd ~/Downloads
echo "d4d6a5470f809f5692e57ea897e4721324837bbf7ccc0e3ea0c63d17b7e7f80d Nessus-10.5.2-ubuntu1404_amd64.deb" > sha256sum_nessus
sha256sum -c sha256sum_nessus
```

Nessus installation
```bash
sudo apt install ./Nessus-10.5.2-ubuntu1404_amd64.deb 
```

# Usage

Starting Nessus
```bash
sudo systemctl start nessusd.service
```

Launch a browser and navigate to 
```
https://127.0.0.1:8834
```
