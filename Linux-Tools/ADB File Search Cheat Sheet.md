# ADB File Search Cheat Sheet

## 🔌 Connection
```bash
# Connect to device
adb connect IP:5555
adb devices

# Restart ADB
adb kill-server && adb start-server

# Disconnect
adb disconnect
```

## 🔍 Basic Search
```bash
# Search by name
adb shell find /sdcard -name "file.txt"
adb shell find /sdcard -iname "file.txt"  # case insensitive

# Wildcard search
adb shell find /sdcard -name "*.jpg"
adb shell find /sdcard -name "photo*"

# Multiple patterns
adb shell find /sdcard \( -name "*.jpg" -o -name "*.png" \)
```

## 📁 Common Directories
```bash
# Internal storage
adb shell find /sdcard -name "target"

# Downloads
adb shell find /sdcard/Download -name "*.pdf"

# Camera photos
adb shell find /sdcard/DCIM -name "IMG_*.jpg"

# App data (root)
adb shell su -c "find /data/data -name '*.db'"
```

## ⚡ Quick Searches
```bash
# Images
adb shell find /sdcard -name "*.jpg" -o -name "*.png" -o -name "*.gif"

# Documents
adb shell find /sdcard -name "*.pdf" -o -name "*.doc" -o -name "*.txt"

# Media files
adb shell find /sdcard -name "*.mp4" -o -name "*.mp3" -o -name "*.avi"

# Config files
adb shell find /sdcard -name "*.xml" -o -name "*.json" -o -name "*.config"
```

## 🎯 Advanced Search
```bash
# By size
adb shell find /sdcard -size +10M    # >10MB
adb shell find /sdcard -size -1M     # <1MB

# By time
adb shell find /sdcard -mtime -1     # last 24h
adb shell find /sdcard -mtime -7     # last 7 days

# With details
adb shell find /sdcard -name "*.jpg" -exec ls -la {} \;

# Limit depth
adb shell find /sdcard -maxdepth 2 -name "*.jpg"
```

## 📊 File Operations
```bash
# Pull files to computer
adb pull /sdcard/file.txt ./

# Push files to device
adb push ./file.txt /sdcard/

# Delete files
adb shell rm /sdcard/unwanted.file

# Create dir
adb shell mkdir /sdcard/new_folder
```

## 🛠️ Useful Tricks
```bash
# Hide errors
adb shell find /data -name "*.db" 2>/dev/null

# Count results
adb shell find /sdcard -name "*.jpg" | wc -l

# Search with grep
adb shell ls -R /sdcard | grep "pattern"

# Root search
adb shell su -c "find /system -name 'file'"
```

## 🚀 One-Liners
```bash
# Find all photos modified recently
adb shell find /sdcard -name "*.jpg" -mtime -7

# Find large videos
adb shell find /sdcard -name "*.mp4" -size +50M

# Find databases and configs
adb shell find /sdcard \( -name "*.db" -o -name "*.conf" \)

# Quick media scan
adb shell find /sdcard -name "*.mp3" -o -name "*.mp4" -o -name "*.jpg"
```

## ⚠️ Quick Notes
- Use `2>/dev/null` to hide permission errors
- Root required for `/data/` and `/system/` searches
- `adb connect IP:5555` for WiFi devices
- Always verify with `adb devices` first

---

**Shortcut**: Bookmark this cheat sheet for quick reference! 🚀