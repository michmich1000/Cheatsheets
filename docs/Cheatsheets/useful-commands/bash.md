# Bash

## Search for files

```text
find / -iname "*user.txt*" 2>/dev/null
updatedb && locate <filename>
```

## Services listening

```text
netstat -latupen |grep LISTEN
```

## Process running

```text
ps faux
```

## Disk space

```text
df -h
du -sh
```

## Netcat send file

```text
nc -l -p 1234 > out.file => listener 
nc -w 3 [destination] 1234 < out.file => sender
```

## Nmap parsing

Hosts up

```text
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up.txt
```

Open Ports

```text
cat *.nmap | grep -i "tcp open" | cut -d "/" -f1 | sort -u | paste -sd ';'
```

## Speak to other users

```text
write tta /dev/pts/23
echo "hello" |wall
```

## Nginx syslink

```text
in "enable" do : ln -s ../site-avaible/ta-conf .
```



