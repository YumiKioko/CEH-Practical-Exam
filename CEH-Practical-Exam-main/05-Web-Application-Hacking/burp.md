## 🚀 Starting Burp Suite

- Launch via GUI or CLI:
```
   burpsuite
```

## 🧰 Core Tools

|Tool|Description|
|---|---|
|**Proxy**|Intercepts browser traffic|
|**Target**|Site map, scope, structure|
|**Repeater**|Manual request replay|
|**Intruder**|Automated fuzzing|
|**Scanner** (Pro)|Vulnerability scanning|
|**Decoder**|Encode/decode data|
|**Comparer**|Diff requests/responses|
|**Extender**|Add BApps and custom extensions|

## 🌐 Proxy

- 🔧 Intercept: Modify in-transit requests/responses
    
- 🎯 Scope: Limit what Burp captures/scans
```
Target → Scope → Add
```

## 📦 Repeater

- 🔁 Re-send modified requests
    
- Great for testing:
    
    - Authentication
        
    - IDORs
        
    - Parameter tampering
        

---

## 🤖 Intruder

Automated fuzzing engine for:

- Brute force (logins, tokens, etc.)
    
- Fuzzing for injection points
    
- Testing rate-limiting

### 🔢 Attack Types

|Type|Purpose|
|---|---|
|Sniper|Single payload across one param|
|Battering Ram|Same payload to all positions|
|Pitchfork|One-to-one payload sets|
|Cluster Bomb|All combinations of payloads|
## 🔍 Scanner (Pro Only)

- Passive & active scanning
    
- Detects:
    
    - XSS
        
    - SQLi
        
    - CSRF
        
    - Open redirects
        
    - Server misconfigs

## 🧪 Common Use Cases

### 🔐 Login Bruteforce (Intruder)

1. Capture POST request
    
2. Send to Intruder
    
3. Set payload positions for `username` and/or `password`
    
4. Load a wordlist
    
5. Start attack
    

### 🧵 Fuzzing Parameters

1. Send request to Intruder
    
2. Highlight `id=`, `q=`, or other params
    
3. Insert payload positions
    
4. Load payloads (e.g., SQL, XSS)
    
5. Observe responses
    

---

## 🧬 Decoder

- Convert:
    
    - URL <=> Plaintext
        
    - Base64 <=> Binary
        
    - Hex
        
- Smart decode mode guesses format

## 📑 Comparer

- Byte-wise and word-wise diffing
    
- Useful for:
    
    - Error messages
        
    - Response length changes
        
    - Authentication token changes
        

---

## 🔌 Extender

- Add **BApps** (Burp Apps / plugins)
    
- Examples:
    
    - **Autorize** – Test for auth bypass
        
    - **ActiveScan++** – Adds extra scan checks
        
    - **Logger++** – Advanced logging


## 📋 Hotkeys

|Action|Shortcut|
|---|---|
|Send to Repeater|`Ctrl + R`|
|Send to Intruder|`Ctrl + I`|
|Forward (Proxy)|`Ctrl + F`|
|Step (Proxy)|`Ctrl + S`|
|Drop (Proxy)|`Ctrl + D`|
## ⚙️ Useful Settings

- **Disable intercept** when not needed
    
- Enable **follow redirects** in Repeater
    
- Increase thread count in Intruder for faster brute-forcing
    
- Use **Logger++** to log everything
    

---

## 📁 Save Work

- Project files (`.burp`) can save entire sessions:
    
    - HTTP history
        
    - Site map
        
    - Repeater tabs
        
    - Notes
        

---

## 🛠 Recommended BApps

|Name|Purpose|
|---|---|
|Autorize|Auth bypass detection|
|ActiveScan++|Improved scanning|
|Logger++|Logs all HTTP traffic|
|CSP Auditor|Detect weak CSP headers|
|Turbo Intruder|High-speed fuzzing|
