 Mobile Security Tools

 Android Security

 Static Analysis
- apktool: APK decompilation
- jadx: Java decompiler
- dex2jar: DEX to JAR converter
- jd-gui: Java decompiler GUI

 Dynamic Analysis
- adb: Android Debug Bridge
- frida: Dynamic instrumentation
- objection: Runtime mobile exploration

 Reverse Engineering
- ghidra: NSA reverse engineering tool
- radare2: Binary analysis framework

 iOS Security

 Static Analysis
- class-dump: Objective-C class dumping
- otool: Object file tool
- nm: Symbol table tool

 Dynamic Analysis
- frida: Dynamic instrumentation
- cycript: Runtime manipulation
- lldb: LLVM debugger

 Cross-Platform Tools

 Mobile Security Framework (MobSF)
- Static Analysis: Análise estática completa
- Dynamic Analysis: Análise dinâmica
- Web Interface: Interface web

 Drozer
- Android Security Assessment: Framework de teste Android

 Scripts Úteis

 APK Analysis
apktool d app.apk
jadx app.apk
dex2jar app.apk

 ADB Commands
adb devices
adb shell
adb install app.apk
adb pull /path/to/file

 Frida
frida-ps -U
frida -U -f com.example.app -l script.js

 Objection
objection -g com.example.app explore

 MobSF
python manage.py runserver