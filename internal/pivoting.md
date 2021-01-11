# Pivoting

## Forward ports or create a socks proxy

* [chisel](https://github.com/jpillora/chisel)
* plink.exe
* meterpreter
* ssh -D
* [reGeorg](https://github.com/sensepost/reGeorg)

We can then use proxychains for any tool that has no buit-in options to specify a socks proxy.

```text
sudo vim /etc/proxychains.conf => changer le port du proxysocks proxychains
proxychains wpscan --url <url> 
wpscan --url <url> --proxy socks5://127.0.0.1:9517 --force
```

Burp =&gt; User Options =&gt; Socks Proxy

## nmap like

**PortqryUI \(Nmap like for windows\)**

```text
netstat -nlt | awk -F : '/\<tcp\>/ {split($2,a," "); print a[1]}' | xargs -I % bash -c 'echo -ne "\033[1;33m[+]\033[m Port %:\t$(timeout 1 cat </dev/tcp/127.0.0.1/%)\n"'
netstat -nlt | grep 'tcp ' | grep -Eo "[1-9][0-9]*" | xargs -I {} sh -c "echo "" | nc -v -n -w1 127.0.0.1 {}"
```

