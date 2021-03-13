# Fail2ban

```bash
fail2ban-client status # to list all jail
fail2ban-client status <jail>
fail2ban-client set <jail> unbanip XX.XX.XX.XX # To unban someone
fail2ban-client -vvv set <jail> banip XX.XX.XX.XX # To ban someone
```

you also can do this to get all banned ip from jail `zgrep 'Ban' /var/log/fail2ban.log* | grep <jail>`
 

>since 0.10 version u can use `unban -all`
