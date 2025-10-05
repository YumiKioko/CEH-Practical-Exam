# ADB File Search Guide

## Initial Connection

### Connecting to Devices
```bash
# Connect to device over WiFi
adb connect 192.168.1.100:5555

# Connect to device over USB
adb devices

# Connect to multiple devices
adb connect 192.168.1.100:5555
adb connect 192.168.1.101:5555

# List connected devices
adb devices -l

# Disconnect specific device
adb disconnect 192.168.1.100:5555

# Disconnect all devices
adb disconnect
```

### Connection Troubleshooting
```bash
# Restart ADB server
adb kill-server
adb start-server

# Check device status
adb devices

# Reset connection
adb tcpip 5555
adb connect 192.168.1.100:5555
```

## Basic File Search Commands

### Using `find` Command
```bash
# Search for files by name (case-sensitive)
adb shell find /sdcard -name "filename.txt"

# Case-insensitive search
adb shell find /sdcard -iname "filename.txt"

# Search by pattern/wildcard
adb shell find /sdcard -name "*.jpg"
adb shell find /sdcard -name "photo*.png"

# Search in specific directory
adb shell find /sdcard/DCIM -name "*.jpg"
```

### Using `ls` and `grep`
```bash
# Recursive search with grep
adb shell ls -laR /sdcard | grep "filename"

# Search in current directory only
adb shell ls -la /sdcard | grep "pattern"
```

### Using `locate` Command (if available)
```bash
# Update locate database (requires root)
adb shell su -c "updatedb"

# Search using locate
adb shell locate "filename"
```

## Advanced Search Options

### Search by File Type
```bash
# Find all PDF files
adb shell find /sdcard -name "*.pdf"

# Find all image files
adb shell find /sdcard \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" \)

# Find all video files
adb shell find /sdcard \( -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" \)
```

### Search by File Size
```bash
# Find files larger than 10MB
adb shell find /sdcard -size +10M

# Find files smaller than 1MB
adb shell find /sdcard -size -1M

# Find files between 1MB and 10MB
adb shell find /sdcard -size +1M -size -10M
```

### Search by Modification Time
```bash
# Find files modified in last 24 hours
adb shell find /sdcard -mtime -1

# Find files modified in last 7 days
adb shell find /sdcard -mtime -7

# Find files modified more than 30 days ago
adb shell find /sdcard -mtime +30
```

## Common Search Directories

### User Data Directories
```bash
# Internal storage
adb shell find /sdcard -name "target_file"

# External SD card (if available)
adb shell find /storage -name "target_file"

# App data directories
adb shell find /data/data -name "*.db" 2>/dev/null

# System directories
adb shell find /system -name "file.xml" 2>/dev/null
```

### Application-Specific Directories
```bash
# WhatsApp media
adb shell find /sdcard/WhatsApp -name "*.jpg"

# DCIM camera folder
adb shell find /sdcard/DCIM -name "IMG_*.jpg"

# Download folder
adb shell find /sdcard/Download -name "*.pdf"
```

## Practical Search Examples

### 1. Find Configuration Files
```bash
# Search for config files
adb shell find /sdcard -name "*.config" -o -name "*.conf" -o -name "config.xml"
```

### 2. Find Database Files
```bash
# Find SQLite databases
adb shell find /sdcard -name "*.db" -o -name "*.sqlite" -o -name "*.db3"
```

### 3. Find Log Files
```bash
# Find log files
adb shell find /sdcard -name "*.log" -o -name "log.txt" -o -name "*.logcat"
```

### 4. Find Backup Files
```bash
# Find backup files
adb shell find /sdcard -name "*.bak" -o -name "*.backup" -o -name "*~"
```

## Enhanced Search Scripts

### Multi-pattern Search Script
```bash
#!/bin/bash
# search_files.sh
echo "Searching for files on device..."

# Search for multiple file types
adb shell find /sdcard \( \
  -name "*.txt" -o \
  -name "*.pdf" -o \
  -name "*.doc" -o \
  -name "*.docx" -o \
  -name "*.jpg" -o \
  -name "*.png" \) \
  2>/dev/null
```

### Recursive Search with Details
```bash
#!/bin/bash
# detailed_search.sh
SEARCH_TERM=$1

if [ -z "$SEARCH_TERM" ]; then
    echo "Usage: $0 <search_term>"
    exit 1
fi

echo "Searching for: $SEARCH_TERM"
adb shell find /sdcard -name "*$SEARCH_TERM*" -exec ls -la {} \; 2>/dev/null
```

## Root Access Required Searches

### System File Search (Root)
```bash
# Search system files (requires root)
adb shell su -c "find /system -name '*.apk'"

# Search data partition
adb shell su -c "find /data -name '*.db'"

# Search entire device
adb shell su -c "find / -name 'filename' 2>/dev/null"
```

### Package-related Searches
```bash
# Find app data for specific package
adb shell su -c "find /data/data/com.example.app -name '*.db'"

# List all APK locations
adb shell su -c "find / -name '*.apk' 2>/dev/null"
```

## File Operations via ADB

### Copy Files to/from Device
```bash
# Pull file from device to computer
adb pull /sdcard/example.txt ./downloads/

# Push file from computer to device
adb push ./file.txt /sdcard/

# Pull multiple files
adb pull /sdcard/DCIM/ ./photos/
```

### File Management
```bash
# Delete file
adb shell rm /sdcard/unwanted.file

# Create directory
adb shell mkdir /sdcard/new_folder

# Copy file
adb shell cp /sdcard/file1.txt /sdcard/backup/file1.txt

# Move file
adb shell mv /sdcard/old.txt /sdcard/new.txt
```

## Useful ADB Search Tips

### 1. Redirect Errors to /dev/null
```bash
# Suppress permission denied errors
adb shell find /data -name "*.db" 2>/dev/null
```

### 2. Combine with Regular Expressions
```bash
# Complex pattern matching
adb shell find /sdcard -regex '.*/202[0-9]-[0-9][0-9]-[0-9][0-9].*\.jpg'
```

### 3. Limit Search Depth
```bash
# Search only 2 levels deep
adb shell find /sdcard -maxdepth 2 -name "*.jpg"
```

### 4. Count Results
```bash
# Count number of JPG files
adb shell find /sdcard -name "*.jpg" | wc -l
```

## Common Issues and Solutions

### Permission Denied Errors
```bash
# Use root access if available
adb shell su -c "find /data -name 'file'"

# Or redirect errors
adb shell find /data -name "file" 2>/dev/null
```

### Device Not Found
```bash
# Check device connection
adb devices

# Ensure USB debugging is enabled
adb kill-server
adb start-server
```

### No Space Left on Device
```bash
# Clear some space before large operations
adb shell rm -f /sdcard/Download/*.tmp
```

## Quick Reference Cheatsheet

```bash
# Connection
adb connect 192.168.1.100:5555
adb devices

# Basic search
adb shell find /sdcard -name "filename"

# Case insensitive
adb shell find /sdcard -iname "filename"

# Multiple file types
adb shell find /sdcard \( -name "*.jpg" -o -name "*.png" \)

# With file details
adb shell find /sdcard -name "*.jpg" -exec ls -la {} \;

# Recent files
adb shell find /sdcard -mtime -7 -name "*.jpg"

# File operations
adb pull /sdcard/file.txt ./
adb push file.txt /sdcard/
```

## Security Considerations

### Legal Usage
- Only search devices you own or have permission to access
- Respect privacy and data protection laws
- Use for legitimate troubleshooting and development

### Best Practices
- Always disconnect after use
- Avoid modifying system files without proper knowledge
- Backup important data before operations

This guide provides comprehensive ADB file search capabilities starting from device connection through advanced file operations.