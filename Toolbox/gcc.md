> The GNU Compiler Collection is an optimizing compiler produced by the GNU Project supporting various programming languages, hardware architectures and operating systems.
> 
> GCC is a key component of the GNU toolchain and the standard compiler for most projects related to GNU and Linux, including the Linux kernel.


#Linux_Privilege_Escalation #Vulnerablity_Exploitation 

# Usage

Using `gcc` on Linux to compile exploit
```bash
gcc cve-2017-16995.c -o cve-2017-16995
```
- Keeping in mind that when compiling code, we must match the architecture of our target.
- This is especially important in situations where the target machine does not have a compiler and we are forced to compile the exploit on our attacking machine or in a sandboxed environment that replicates the target OS and architecture.

# Possible Errors

## fatal error: cannot execute ‘cc1plus’: execvp: No such file or directory

Possible fixes for error
```
sudo apt-get update
sudo apt-get install --reinstall build-essential
sudo apt install mingw-w64
```

