
## MobSF - Mobile Security Framework

🧪 MobSF - Mobile Security Framework

MobSF is an automated framework for analyzing Android and iOS apps (static and dynamic).

### 🔧 Installation (Docker)

```
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
```

```
cd Mobile-Security-Framework-MobSF
```

```
docker-compose up
```
Web interface usually runs on `http://127.0.0.1:8000`


## 📦 Supported Analysis

| Type    | Features                                |
| ------- | --------------------------------------- |
| Static  | Decompiles APK/IPA, scans code, secrets |
| Dynamic | Instrumented sandbox with Frida & ADB   |
| API     | Programmatic scanning via REST API      |

## 📂 Static Analysis

1. Upload APK or IPA file    
2. Get code insights, API calls, permissions
3. View hardcoded secrets, trackers, SSL info

---

## 📱 Dynamic Analysis

1. Connect real/emulator device via ADB    
2. Start dynamic scan
3. Analyze runtime behavior, memory

---

## 🧠 Example: Scan APK

```
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: <API_KEY>"
```
## ⚠️ Notes

- Requires emulator or device for dynamic scan
- Use latest Frida server for dynamic tests
- Can be scripted for CI/CD integration

















