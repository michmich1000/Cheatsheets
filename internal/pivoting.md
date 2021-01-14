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

```bash
netstat -nlt | awk -F : '/\<tcp\>/ {split($2,a," "); print a[1]}' | xargs -I % bash -c 'echo -ne "\033[1;33m[+]\033[m Port %:\t$(timeout 1 cat </dev/tcp/127.0.0.1/%)\n"'
netstat -nlt | grep 'tcp ' | grep -Eo "[1-9][0-9]*" | xargs -I {} sh -c "echo "" | nc -v -n -w1 127.0.0.1 {}"
```

