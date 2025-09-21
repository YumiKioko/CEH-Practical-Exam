#!/bin/bash

echo "=== Android ADB Automation Script ==="

# 1. Check and install adb if missing
if ! command -v adb &> /dev/null; then
  echo "[*] adb not found. Installing..."
  sudo apt-get update && sudo apt-get install adb -y
else
  echo "[*] adb is installed."
fi

# 2. Prompt for Android device IP
read -p "Enter Android device IP (e.g. 192.168.1.10): " DEVICE_IP

# 3. Connect to device
echo "[*] Connecting to $DEVICE_IP..."
adb connect "$DEVICE_IP:5555"

# 4. List devices
echo "[*] Listing connected devices..."
adb devices -l

# 5. Open shell?
read -p "Open adb shell now? (y/n): " OPEN_SHELL
if [[ "$OPEN_SHELL" =~ ^[Yy]$ ]]; then
  echo "[*] Opening shell on $DEVICE_IP"
  adb -s "$DEVICE_IP:5555" shell
fi

# 6. Pull file from device
read -p "Pull file from device? (y/n): " PULL_FILE
if [[ "$PULL_FILE" =~ ^[Yy]$ ]]; then
  read -p "Enter full path of file on device (e.g. /sdcard/Download/secret.txt): " FILE_PATH
  read -p "Enter local destination directory (e.g. ~/Desktop): " LOCAL_DIR
  mkdir -p "$LOCAL_DIR"
  echo "[*] Pulling $FILE_PATH to $LOCAL_DIR"
  adb -s "$DEVICE_IP:5555" pull "$FILE_PATH" "$LOCAL_DIR"
fi

echo "=== Done ==="
