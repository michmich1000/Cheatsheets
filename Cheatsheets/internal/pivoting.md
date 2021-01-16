# Pivoting

## Forward tools

* [chisel](https://github.com/jpillora/chisel)
* plink.exe
* meterpreter
* ssh -D
* [reGeorg](https://github.com/sensepost/reGeorg)

### Proxychains

We can choose one of the forward tools to create a socks proxy and configure Proxychains to route into it the traffic of any pentesting tool that has no buit-in options to specify a socks proxy :

```bash
sudo vim /etc/proxychains.conf => changer le port du proxysocks proxychains
proxychains wpscan --url <url> 
wpscan --url <url> --proxy socks5://127.0.0.1:9517 --force
```

### Burp Socks Proxy

Burp => User Options => Socks Proxy


## Nmap like

**PortqryUI \(Nmap like for windows\)**
