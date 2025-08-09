curl is a powerful command-line tool used to transfer data from or to a server. It's widely used in security testing for sending crafted HTTP requests, interacting with APIs, fuzzing, and automation.
## 📦 Basic Usage

```
curl https://example.com
```
## 🔐 Common Security Use Cases

| Use Case                              | Command Example                                                      |
| ------------------------------------- | -------------------------------------------------------------------- |
| 🔍 Check HTTP Headers                 | `curl -I https://example.com`                                        |
| 🧪 Test for open redirects            | `curl -L "https://target.com?next=http://evil.com"`                  |
| 🛂 Send custom headers (e.g., tokens) | `curl -H "Authorization: Bearer <token>" https://api.com/data`       |
| 💣 Test with different HTTP methods   | `curl -X PUT https://target.com/resource`                            |
| 🛡️ Test HTTPS with verbose SSL info  | `curl -v --ssl https://example.com`                                  |
| 🧱 Send payloads for XSS/SQLi         | `curl -d "search=<script>alert(1)</script>" https://site.com/search` |
| 📤 File Upload via POST               | `curl -F "file=@malware.apk" https://target.com/upload`              |
| 🔁 Follow redirects                   | `curl -L http://example.com`                                         |
| ⌛ Measure response time               | `curl -w "@curl-format.txt" -o /dev/null -s https://example.com`     |
## 🔐 Example: Test API with Custom Headers

```
curl -X GET https://api.target.com/user \
     -H "User-Agent: Mozilla" \
     -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔍 Example: Find Open HTTP Methods

```
curl -X OPTIONS -I https://example.com
```
Look for `Allow:` header response indicating `PUT`, `DELETE`, etc.

## 📂 Example: Brute Force Login Form (Basic)

```
for user in $(cat users.txt); do
  curl -X POST -d "username=$user&password=test" https://example.com/login
done
```

## 📊 Output Control

| Option | Function             |            |
| ------ | -------------------- | ---------- |
| `-s`   | Silent mode          |            |
| `-v`   | Verbose              |            |
| `-o`   | Output to file       |            |
| `-w`   | Custom output format | ## 🧠 Tips |

- Combine with **jq** for JSON parsing
- Use in scripts for recon & automation
- Avoid detection: spoof headers, random agents
- Integrate with tools like **Burp**, **MobSF**, or **Shodan APIs**

































































