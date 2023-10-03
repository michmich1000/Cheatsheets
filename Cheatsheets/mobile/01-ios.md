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

### Search for password


`fridump -s -U "My App"`

`strings *.data > strings.txt`

and now grep into "pass", "password", "secret", "credential" etc


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


### run js from frida

`frida -U -f com.xxx.yyy -l alert.js`

alert script example

```
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;
var handler = new ObjC.Block({ retType: 'void', argTypes: ['object'], implementation: function () {} });

ObjC.schedule(ObjC.mainQueue, function () {
  var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'pwned!', 1);
  var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
})
```

with python : `python3 hook.py alert.js`


```
import frida, sys

with open(sys.argv[1], 'r') as f:
        jscode = f.read()
process = frida.get_usb_device().attach('<APP NAME>')
script = process.create_script(jscode)
print('[ * ] Running alert on target')
script.load()
sys.stdin.read()
``` 


### run static analysis using frida

`frida --codeshare interference-security/ios-app-static-analysis -U <appName>`  (it will execute this code https://codeshare.frida.re/@interference-security/ios-app-static-analysis/ ) 
