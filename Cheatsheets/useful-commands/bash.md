# Bash

## Alias

```bash
# Clipboard
alias sclip="xclip -selection c"
alias gclip="xclip -selection c -o"

# IPs
grep -ao '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'| sort -u

# SAM hash (from crackmapexec log files)
awk -F: '{print $1":"$3":"$4}' |tr [:upper:] [:lower:] | sort -u
```

## Save output to log file

```bash
<command> | tee -a /tmp/logfile
```

## Compilation

Compile for x86 Linux from a x64 Linux machine

```bash
sudo apt update && sudo apt install -y gcc-multilib 
gcc -Wl,--hash-style=both -m32 <exploit.c>
```

Cross-Compile for x86 Windows from a x64 Linux machine

```bash
sudo apt update && sudo apt install -y mingw-w64
i686-w64-mingw32-gcc <exploit.c>
i686-w64-mingw32-gcc -lws2_32 MS11-046.c
```


## Search for files

```bash
find / -iname "*user.txt*" 2>/dev/null
updatedb && locate <filename>
```

## Services listening

```bash
netstat -latupen |grep LISTEN
```

## Process running

```bash
ps faux
```

## Disk space

```bash
df -h
```

---

## Netcat send file

```bash
# listener
nc -l -p 1234 > out.file

# sender
nc -w 3 <ip_listener> 1234 < in.file
```

---

## Nmap parsing

Hosts up

```bash
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up.txt
```

Open Ports

```bash
cat *.nmap | grep -i "tcp open" | cut -d "/" -f1 | sort -u | paste -sd ';'
```

---

## Nessus parsing

Hosts up

```bash
cat <filename>.csv |grep -i 'tcp",' |cut -d "," -f5 | tr -d '"' |sort -u > perim_up_nessus.txt
```

Open Ports

```bash
cat <filename>.csv |grep -i 'tcp",' |cut -d "," -f7 | tr -d '"' |sort -u | sed -r '/^\s*$/d' | tr "\n" ",  " | rev | cut -c2- |rev | sed 's/, */, /g'
```

## Speak to other users

```bash
who
write <username> /dev/pts/<pts_number>
echo "hello" |wall
```

---

## Nginx syslink

```bash
in "enable" do : ln -s ../site-avaible/<your-conf>.conf .
```

## Docker

Install docker on kali
```sh
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt remove docker docker-engine docker.io && sudo apt install docker-ce -y
```

## SublimeText 

```sh
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add - && sudo apt-get install apt-transport-https && echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list && sudo apt-get update && sudo apt-get install sublime-text
```

### RDP 

```sh
xfreerdp /u:<username> /d:<domain> /pth:[lm]:<nt> /v:<target>
rdesktop -u <username> -p <pass> -r disk:floppy=/tmp/share <target>
```