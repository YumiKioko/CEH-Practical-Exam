## 🔧 Installation
```
pip install frida-tools
```

For Android:
```
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```
## 🧪 Common Use Cases

- Intercept method calls in Android/iOS apps
    
- Bypass SSL pinning
    
- Hook native libraries
    
- Analyze runtime values
    

---

## ▶️ Basic Commands

### List connected devices
```
frida-ls-devices
```

## Attach to app
```
frida -U -n com.example.app
```

## Run a script
```
frida -U -n com.example.app -l script.js
```

## 🧠 Example: Bypass SSL Pinning
```
Java.perform(function () {
    var CertPinning = Java.use("com.example.SSLPinning");
    CertPinning.checkPinning.implementation = function () {
        return true;
    };
});
```

## ⚠️ Notes

- Root/Jailbreak may be required
    
- Hooking sensitive apps may cause crashes
    
- Frida scripts are powerful but detectable















