
- [ ] List the archives of a `borg` repository nicely formatted on the Target Machine
```
sudo borg list --format '{archive}{NL}' /opt/borgbackup/
```
- The --format option uses python’s format string syntax.

- [ ] Extract an archive from a `borg` repository on the Target Machine
```
sudo borg extract --list /opt/borgbackup::some_borg_archive
```

- [ ] Extract an archive from a `borg` repository with python format string syntax on the Target Machine
```
sudo borg extract --list /opt/borgbackup::somebackup_{now}
sudo borg extract --list /opt/borgbackup::somebackup_$(date +"%s")
```

- [ ] Extract an archive from a `borg` directory into standard output on the Target Machine
```
sudo borg extract /opt/borgbackup::home --stdout
```
- Prints archive contents to console

References:
https://borgbackup.readthedocs.io/en/stable/usage/list.html
https://linuxconfig.org/introduction-to-borg-backup