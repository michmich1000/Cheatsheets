# Powershell

## Download file

```powershell
Invoke-WebRequest <file_url> -Outfile <outfile>
```

---

## Import PS1 module

```powershell
import-module <full_path_ps1_file>
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
