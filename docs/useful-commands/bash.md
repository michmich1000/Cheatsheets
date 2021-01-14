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

## Netcat send file

```bash
nc -l -p 1234 > out.file => listener 
nc -w 3 [destination] 1234 < out.file => sender
```

## Nmap parsing

Hosts up

```bash
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up.txt
```

Open Ports

```bash
cat *.nmap | grep -i "tcp open" | cut -d "/" -f1 | sort -u | paste -sd ';'
```

## Speak to other users

```bash
write tta /dev/pts/23
echo "hello" |wall
```

## Nginx syslink

```bash
in "enable" do : ln -s ../site-avaible/ta-conf .
```



