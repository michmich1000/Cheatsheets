# Fail2ban

```bash
fail2ban-client status # to list all jail
fail2ban-client status <jail>
fail2ban-client set <jail> unbanip XX.XX.XX.XX # To unban someone
fail2ban-client -vvv set <jail> banip XX.XX.XX.XX # To ban someone
```

>since 0.10 version u can use `unban -all`
