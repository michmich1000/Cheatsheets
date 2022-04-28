# Red team documentation


## 1. **External recon**

>https://github.com/smicallef/spiderfoot


### Collect email

With peopleScrap (https://github.com/n3tsky/PeopleScrap)

`python3 peopleScrap.py -c <evilcorp> -d <evilcorp.com>`


### Search for subdomains

With Amass

`amass enum -o -v -src -ip -brute -min-for-recursive 2 -share -d <evilcorp.com>`

for passive scan you also can run this one `amass enum -o web-targets.txt -d <evilcorp.com>` 

With Yelaa

`Yelaa osint -d <evilcorp.com>`

With sublist3r

`sublist3r -v -d <evilcorp.com>`

With Subfinder 

`subfinder -d <evilcorp.com>`


### Screenshot of many domain

`Yelaa checkAndScreen -t ./web-targets.txt`


### Search for credentials (leaks)

With Dehashed (https://www.dehashed.com/)

`curl 'https://api.dehashed.com/search?query=domain:<evilcorp.com>' -u mail@exemple.com:11aa22bb33bb44cc55dd66ee77ff88gg -H 'Accept: application/json' > leak.json`


With intelx (https://intelx.io/)

`intelx.py -search <evilcorp.com> -apikey 3a014321-d680-4654-b17f-57fc90c9987a`

With Telegram: 

https://t.me/D3atr0y3d


### Dorks automation 

With FGDS (https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan)

`./FGDS.sh <evilcorp.com>`

### Combo ( subdomains, emails, firstname and lastname)

`theHarvester -d <evilcorp.com> -b all`



## 2. **Internal recon**


