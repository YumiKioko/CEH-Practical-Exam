
# Mobile Hacking Cheat Sheet (Android + iOS)

  
## Android Tools

  

- **Frida** – Dynamic hooking and instrumentation framework.

- **Burp Suite** – Proxy tool for HTTP/HTTPS interception and manipulation.

- **adb (Android Debug Bridge)** – CLI tool to interact with Android devices.

- **MobSF** (Mobile Security Framework)

- **Phonesploit**






## 1. scripts

### 🔹 APK/IPA Enumeration


**Android**

```bash

aapt dump badging app.apk

apktool d app.apk

jadx-gui app.apk

```

### 🔹 Metadata Extraction

  
**Android**

```bash

grep -i 'permission\|activity\|intent' AndroidManifest.xml

```

  

---


Dynamic Analysis

### Android

```bash

frida -U -n com.target.app -l script.js

adb logcat | grep com.target.app

adb shell am start -n com.app/.MainActivity

```


  
---

  
