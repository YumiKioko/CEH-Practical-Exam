# 📱 ADB - Android Debug Bridge

ADB is a command-line tool that allows communication with Android devices for debugging, testing, and system analysis.

---

## 🔧 Installation

- Included in Android SDK Platform Tools
- Download: https://developer.android.com/studio/releases/platform-tools

---

## 🔗 Connect to Device

```
adb devices
adb connect <ip_address>:5555
```

## 🔍 Useful Commands

### File Operations
```
adb pull /sdcard/sample.txt
adb push localfile.txt /sdcard/
```

## Shell Access
```
adb shell
adb shell pm list packages
adb shell dumpsys activity
```
## App Management
```
adb install app.apk
adb uninstall com.example.app
adb logcat
```
## 🛡️ Security Use Cases

- Extract app data for analysis
    
- Dump app memory or activities
    
- Capture logcat during execution
    
- Use with Frida or MobSF

















