## 🌐 Target Configuration

- **Target URL**: e.g. `http://example.com/`
    
- **Port**: Set if non-standard (e.g., `8080`)
    
- **Start Point**: `/` by default (root directory)

## 📁 Wordlists

Use built-in or custom lists:

- Common location:
```
 /usr/share/wordlists/dirbuster/
```
Popular lists:

- `directory-list-2.3-medium.txt`
    
- `directory-list-lowercase-2.3-small.txt`

## ⚙️ Key Options

|Option|Description|
|---|---|
|**Recursive**|Bruteforce subdirectories|
|**Follow redirects**|Handle 3xx responses|
|**Number of Threads**|Set concurrency (10–50 recommended)|
|**File extension list**|Add e.g., `.php,.asp,.bak`|
|**Use blank extension**|Try both with and without extensions|
|**Be recursive**|Enable directory depth search|
|**Use HEAD**|Use `HEAD` instead of `GET` to reduce bandwidth|

## 🧪 Example Use Cases

### Basic Scan
```
Target: http://victim.com/
Wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
Threads: 20
```
### Recursive Bruteforce

✅ Enable “Be recursive” and “Dir only search” for deep enumeration.

---

## 📤 Output

DirBuster allows saving output in:

- **HTML**
    
- **CSV**
    
- **Plaintext**
    

You can also monitor results live from the GUI.

---

## 🆚 DirBuster vs Others

|Tool|Type|Pros|Cons|
|---|---|---|---|
|**DirBuster**|GUI/Java|Good for visual scans|Slower, outdated|
|**Dirb**|CLI|Lightweight, fast|No recursion|
|**Gobuster**|CLI|Fast, modern|Requires Go|
|**FFUF**|CLI|Extremely fast|CLI-only, steep learning curve|

---

## ⚠️ Tips & OPSEC

- Avoid overloading servers with high threads
    
- Set user-agent headers if needed
    
- Respect robots.txt (or not 😈)
    
- Use VPN/Proxy during testing
    
- Don’t test unauthorized systems










































