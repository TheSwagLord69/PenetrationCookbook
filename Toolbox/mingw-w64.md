> A free and open source software development environment to create Microsoft Windows PE applications. It was forked in 2005–2010 from MinGW


#Vulnerability_Exploitation 

Installing the `mingw-w64` cross-compiler in Kali
```bash
sudo apt install mingw-w64
```

Compile the exploit using `mingw-64`
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```

Compiling the code after linking the winsock library
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
ls -lah
```

Cross-Compile the C Code to a 64-bit application
```bash
x86_64-w64-mingw32-gcc add_sus_user.c -o add_sus_user.exe
```