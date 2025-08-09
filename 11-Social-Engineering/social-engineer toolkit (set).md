
## 💡 Key Features

- 🎣 **Phishing Attacks**
- 💻 **Website Cloning**
- 🛠️ **Credential Harvesting**
- 🧬 **Payload Generation**
- 📦 **USB Drop Attacks**
- ☎️ **SMS Spoofing (via 3rd-party APIs)**

---

## 🚀 Installation

### 🐧 On Kali Linux (pre-installed)

```bash
sudo setoolkit
```

### 📦 Manual Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install git python3-venv -y
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
python3 setup.py
```

---

## 🧭 Main Menu Options (Sample)

```text
1) Social-Engineering Attacks
2) Penetration Testing (Fast-Track)
3) Third Party Modules
4) Update the Social-Engineer Toolkit
5) Update SET configuration
6) Exit the Social-Engineer Toolkit
```

---

## 🔍 Core Attack Vectors

### 1. **Spear-Phishing Attack Vector**

- Send a malicious email with a payload or a fake link.
- Options: Credential harvester, malware attachment, etc.

### 2. **Website Attack Vectors**

- Clone a website and host a fake login page.
- Useful for harvesting usernames/passwords.
- Can inject JavaScript keyloggers or Metasploit payloads.

### 3. **Infectious Media Generator**

- Create infected USB/CD payloads.
- Simulates "lost USB" attacks.

### 4. **Create a Payload and Listener**

- Generate backdoors using:

    - Meterpreter reverse shell        
    - Shellcode injection

- Sets up a listener to catch connections.    

---
## 🛡️ Common Use Cases (Red Team)

| Scenario              | Tool Functionality                    |
| --------------------- | ------------------------------------- |
| Phishing Simulation   | Spear Phishing Attack Vector          |
| Credential Harvesting | Website Cloner + Credential Harvester |
| USB Drop Test         | Infectious Media Generator            |
| Payload Delivery      | Python, Bash, PowerShell payloads     |
| Exploit Delivery      | Integration with Metasploit           |

---
## ⚙️ Configuration

Edit `config/set_config` to change:

- SMTP settings (for phishing)    
- Auto listener IP
- Apache web server usage
- Payload options

---
## ✅ Best Practices

- Always get **written permission** for assessments.
- Combine SET with **OSINT tools** like Maltego, Recon-ng.
- Use in isolated environments or VMs.
- Log all activity for audit purposes.
