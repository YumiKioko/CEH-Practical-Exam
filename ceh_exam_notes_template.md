# CEH Practical Exam - Findings Annotation Template

## Exam Information
- **Date:** ___________
- **Start Time:** ___________
- **End Time:** ___________
- **Target Network/Range:** ___________

---

## Quick Reference Section
### Key IPs Found
| IP Address | OS/Service | Priority | Status |
|------------|------------|----------|---------|
|            |            |          |         |
|            |            |          |         |
|            |            |          |         |

### Credentials Found
| Username | Password | Service/Port | IP | Notes |
|----------|----------|--------------|----|----- |
|          |          |              |    |       |
|          |          |              |    |       |

---

## Reconnaissance Phase

### Network Discovery
**Command Used:** `nmap -sn [network_range]`
```
[Paste nmap results here]
```

**Live Hosts Identified:**
- [ ] IP: __________ (Notes: ___________)
- [ ] IP: __________ (Notes: ___________)
- [ ] IP: __________ (Notes: ___________)

### Port Scanning
**Command Used:** `nmap -sS -sV -O -A [target_ip]`
```
[Paste detailed nmap results here]
```

**Key Open Ports:**
- [ ] **IP:** __________ **Port:** ____ **Service:** __________ **Version:** __________
- [ ] **IP:** __________ **Port:** ____ **Service:** __________ **Version:** __________
- [ ] **IP:** __________ **Port:** ____ **Service:** __________ **Version:** __________

---

## Vulnerability Assessment

### Target 1: [IP Address]
**Service Enumeration:**
- [ ] **HTTP/HTTPS (80/443):** 
  - Directory enumeration: `dirb/gobuster results`
  - Web technology: __________
  - Potential vulnerabilities: __________

- [ ] **SSH (22):** 
  - Version: __________
  - Banner info: __________
  - Brute force attempt: __________

- [ ] **FTP (21):** 
  - Anonymous access: [ ] Yes [ ] No
  - Version: __________
  - Files found: __________

- [ ] **SMB (139/445):** 
  - Shares enumerated: __________
  - Access level: __________
  - Files of interest: __________

**Vulnerabilities Identified:**
1. **CVE/Vuln:** __________ **Severity:** __________ **Exploitable:** [ ] Yes [ ] No
2. **CVE/Vuln:** __________ **Severity:** __________ **Exploitable:** [ ] Yes [ ] No

### Target 2: [IP Address]
[Repeat structure above for each target]

---

## Exploitation Phase

### Exploit Attempt 1
- **Target:** __________
- **Vulnerability:** __________
- **Tool/Exploit Used:** __________
- **Command:** `__________`
- **Result:** [ ] Success [ ] Failed
- **Shell/Access Gained:** __________
- **Privilege Level:** __________
- **Next Steps:** __________

### Exploit Attempt 2
[Repeat structure for each exploit attempt]

---

## Post-Exploitation

### System 1: [IP Address]
**Initial Access:**
- **User:** __________ **Shell Type:** __________ **Time:** __________

**Privilege Escalation:**
- **Method:** __________
- **Command:** `__________`
- **Result:** [ ] Success [ ] Failed
- **Root/Admin Access:** [ ] Yes [ ] No

**Data Collection:**
- [ ] **Flags Found:** __________
- [ ] **Sensitive Files:** __________
- [ ] **Password Hashes:** __________
- [ ] **Network Configuration:** __________

**Persistence:**
- **Method:** __________
- **Backdoor Created:** [ ] Yes [ ] No
- **Location:** __________

### System 2: [IP Address]
[Repeat structure for each compromised system]

---

## Answer Submission Tracking

### Question 1: [Question text]
- **Answer:** __________
- **Evidence Location:** __________
- **Screenshot Taken:** [ ] Yes [ ] No
- **Confidence Level:** [ ] High [ ] Medium [ ] Low

### Question 2: [Question text]
- **Answer:** __________
- **Evidence Location:** __________
- **Screenshot Taken:** [ ] Yes [ ] No
- **Confidence Level:** [ ] High [ ] Medium [ ] Low

[Continue for all exam questions]

---

## Tools Used
- [ ] Nmap: `commands used`
- [ ] Metasploit: `exploits used`
- [ ] Burp Suite: `findings`
- [ ] Nikto: `web vulnerabilities`
- [ ] John the Ripper: `password cracking`
- [ ] Hydra: `brute force attacks`
- [ ] Dirb/Gobuster: `directory enumeration`
- [ ] SQLmap: `SQL injection`
- [ ] Other: __________

---

## Critical Findings Summary
1. **High Priority:** __________
2. **Medium Priority:** __________
3. **Flags/Answers Found:** __________

---

## Time Management
- **Phase 1 (Recon):** Started: _____ Completed: _____
- **Phase 2 (Scanning):** Started: _____ Completed: _____
- **Phase 3 (Exploitation):** Started: _____ Completed: _____
- **Phase 4 (Post-Exploit):** Started: _____ Completed: _____
- **Phase 5 (Documentation):** Started: _____ Completed: _____

---

## Notes & Reminders
- **Technical Issues:** __________
- **Commands That Worked:** __________
- **Commands That Failed:** __________
- **Things to Remember:** __________
- **Follow-up Actions:** __________