# IOS Penetration Testing

## **Setup**

Download : 

>https://mobexler.com

password : `12345`


> ipad root default password : `alpine` 

## [Frida](https://github.com/frida)

check if your device is connected : `ideviceinfo`

### List apps running :

`frida-ps -Uai`


### Check App 

`frida-trace -U <AppName> -m "-[NSURL* *HTTP*]"`


## Objection 

run `frida-ps -Uai` then `objection -g <Identifier> explore`


`ios info binary`


`ls` then `ios plist cat Info.plist`


### dump password from safari :

`ios nsurlcredentialstorage dump`

### Check for creds

`ios keychain dump`

### ssl pinning

`ios sslpinning disable`


### Search for last research 

`ios nsuserdefaults get` and check `RecentWebSearches` 


### Search for cookie 

`ios cookies get`
### List module in memory

`memory list modules`

`memory list exports <module_name>`


### Hooking on class


`ios hooking watch class iGoat_Swift.PlistStorageExerciseViewController`


### Hooking on method

`ios hooking watch method "-[iGoat_Swift.BinaryCookiesExerciseVC verifyItemPressed]" --dump-args --dump-backtrace --dump-return`


### env


`env` 

```
CachesDirectory    /var/mobile/Containers/Data/Application/xxx/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/xxx/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/xxx/Library
``` 
