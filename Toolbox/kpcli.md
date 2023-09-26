> A simple command line tool to interact with KeePassX (.kdbx) databases.


#KeePass #Password_Attacks

# Download

Install
```
sudo apt install kpcli
```

# Usage

Open KeePass database
```
kpcli --kdb=Database.kdbx
```
- Requires master password

Show groups and entries
```
ls
```

Show password of entries
```
show -f hentaisalesman
show -f 1
```

Save as .kdb
```
saveas out.kdb
```