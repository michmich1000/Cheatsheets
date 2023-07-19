# Kerberos

## 1. **How it work**

### Reminder

- The user authenticates to the kerberos server (usually the DC)

- The DC sends a TGT that says "I certify that this is who he says he is".

- The user requests a TGS from the service he wants with his TGT

- The service checks that he has the right to access, if yes it sends him a TGS

- The user uses his TGS to access the service

>The TGT is signed with the NT of the krbtgt account

>The TGS is signed with the NT of the machine account
