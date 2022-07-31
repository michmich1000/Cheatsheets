# Bash

## Alias

```bash
# Clipboard
alias sclip="xclip -selection c"
alias gclip="xclip -selection c -o"

# IPs
grep -ao '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'| sort -u

# IP Ranges 
awk -F. '{print $1"."$2"."$3".0/24"}'

## Nmap parsing (Hosts up)
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u

## Nmap parsing (Open Ports)
cat *.nmap | grep -i " open" | cut -d "/" -f1 | sort -u | paste -sd ','

## Nessus parsing (Hosts up)
cat *.csv |grep -i 'tcp",' |cut -d "," -f5 | tr -d '"' |sort -u

## Nessus parsing (Open Ports) 
cat *.csv |grep -i 'tcp",' |cut -d "," -f7 | tr -d '"' |sort -u | sed -r '/^\s*$/d' | tr "\n" ",  " | rev | cut -c2- |rev | sed 's/, */, /g' | cut -f 2- -d ' '

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
ncdu -x 
```

---

## Netcat send file

```bash
# listener
nc -l -p 1234 > out.file

# sender
nc -w 3 <listener_ip> 1234 < in.file
```

---


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

## RDP 

```sh
xfreerdp /u:<username> /d:<domain> /pth:[lm]:<nt> /v:<target>
rdesktop -u <username> -p <pass> -r disk:floppy=/tmp/share <target>
```

## Fail2ban

```bash
fail2ban-client status # to list all jail
fail2ban-client status <jail>
fail2ban-client set <jail> unbanip XX.XX.XX.XX # To unban someone
fail2ban-client -vvv set <jail> banip XX.XX.XX.XX # To ban someone
```

you also can do this to get all banned ip from jail `zgrep 'Ban' /var/log/fail2ban.log* | grep <jail>`
 

>since 0.10 version u can use `unban -all`


## veracrypt

### How to create volume
`veracrypt -t --create report.vc --hash sha512 --encryption AES --filesystem ext4 --volume-type normal -k "" --pim 0 --size 200M` 

> You can also add --password test but, isn't recommended

### How to open volume

`veracrypt <PathToFile.vc> /media/<YourFolder>` 
>By default it will mount into /media/veracrypt<X>

### How to lock volume

`veracrypt -d <PathToFile.vc>`
>By default -d without vc file will lock every container



## One-line install

### Install Golang

```bash
sudo apt update && sudo apt install -y golang subfinder && export GOROOT=/usr/lib/go && export GOPATH=$HOME/go && export PATH=$GOPATH/bin:$GOROOT/bin:$PATH;
```

### Install Docker

```sh
# Install docker from kali repo
sudo apt update && sudo apt install -y docker.io && sudo usermod -aG docker $USER && exec sg docker newgrp `id -gn`

# Install docker from docker repo
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt remove docker docker-engine docker.io && sudo apt install docker-ce -y
```

### Install SublimeText 

```sh
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add - && sudo apt-get install apt-transport-https && echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list && sudo apt-get update && sudo apt-get install sublime-text
```


### Install Arsenal 

Inventory of useful commands

```bash
# Install Arsenal
git clone https://github.com/Orange-Cyberdefense/arsenal.git && cd arsenal && ./addalias.sh && ./run

# Install Arsenal (with package)
git clone https://github.com/Orange-Cyberdefense/arsenal.git && cd arsenal && sudo python3 setup.py install; cd arsenal; python3 app.py
```

