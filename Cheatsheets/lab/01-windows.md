# Lab windows

## 1. **Installation**

### Download iso

go to microsoft and download .iso and select windows pro (if you choose another version you will not have the RDP)


### Use Local account instead of microsoft account

microsoft has hidden the installation button without internet to make it reappear and use a local account do the following actions: 

`shift + F10` you will have prompt and type OOBE\BYPASSNRO

another way is to use the following email address: no@thankyou.com and type a random password


### Create local admin

```
net user pwn pwn /add
net localgroup administrators /add
```

### Disable UAC

```
reg.exe ADD HKLM SOFTWARE Microsoft Windows CurrentVersion Policies System / v EnableLUA / t REG_DWORD / d 0 / f .
or 
go to HKEY_LOCAL_MACHINE SOFTWARE Microsoft Windows CurrentVersion Policies System and set EnableLUA to 0
```


## 2. **Enable Windows**

open powershell as admin and run `irm https://massgrave.dev/get | iex`