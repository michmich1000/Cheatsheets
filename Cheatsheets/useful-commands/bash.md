# Bash

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
du -sh
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
