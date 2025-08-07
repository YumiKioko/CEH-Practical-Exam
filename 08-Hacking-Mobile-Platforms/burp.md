
## 🔌 Key Features

| Tool           | Description                          |
|----------------|--------------------------------------|
| Proxy          | Intercepts HTTP/S traffic            |
| Repeater       | Manual request modification          |
| Intruder       | Automated fuzzing and brute-forcing  |
| Scanner (Pro)  | Automated vulnerability detection     |
| Decoder        | Encode/decode base64, URL, etc.      |

---

## 🧪 Common Use Cases

- Test login forms and session handling
- Analyze and manipulate API traffic
- Identify XSS, SQLi, CSRF, SSRF
- Map application content

---

## 🛠️ Configuration

### Proxy Setup

1. Start Burp
2. Configure browser to use `127.0.0.1:8080`
3. Install Burp CA certificate in browser

---

## 🧠 Example: Fuzz Login with Intruder

1. Send login request to Intruder
2. Set position on username or password
3. Load password list (e.g., SecLists)
4. Start attack

