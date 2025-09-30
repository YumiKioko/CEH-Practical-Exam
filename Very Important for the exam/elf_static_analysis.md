# ELF Static Analysis Guide - Linux Binaries & msfvenom Payloads

**WARNING:** Only analyze malware in isolated VMs. Never execute suspicious binaries on production systems.

---

## 1. File Identification & Hashing

### Calculate Hashes
```bash
# SHA256 (primary for malware identification)
sha256sum payload.elf

# All common hashes
md5sum payload.elf
sha1sum payload.elf
sha256sum payload.elf
sha512sum payload.elf

# One-liner for all hashes
for hash in md5 sha1 sha256 sha512; do 
  echo -n "$hash: "; ${hash}sum payload.elf | awk '{print $1}'
done

# SSDEEP (fuzzy hashing for similarity detection)
ssdeep payload.elf
```

### File Type & Format Detection
```bash
# Basic file identification
file payload.elf
file -b payload.elf  # Brief output

# Detailed ELF information
readelf -h payload.elf

# Check if it's 32-bit or 64-bit
file payload.elf | grep -o "ELF [0-9]*-bit"

# Check architecture
readelf -h payload.elf | grep Machine
```

**Expected output for ELF:**
```
payload.elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
statically linked, no section header
```

### File Metadata & Timestamps
```bash
# File statistics
stat payload.elf

# Creation/modification times
stat -c 'File: %n
Size: %s bytes
Access: %x
Modify: %y
Change: %z' payload.elf

# File permissions
ls -lh payload.elf
stat -c '%A %a' payload.elf
```

---

## 2. ELF Header Analysis

### Read ELF Header
```bash
# Complete ELF header
readelf -h payload.elf

# Key fields to examine:
readelf -h payload.elf | grep -E "Class|Data|Type|Machine|Entry"
```

**Key Information:**
- **Class**: ELF32 or ELF64
- **Data**: Little/Big endian
- **Type**: EXEC (executable), DYN (shared object), REL (relocatable)
- **Machine**: x86-64, ARM, MIPS, etc.
- **Entry point**: Memory address where execution starts

### Program Headers
```bash
# List program headers (segments)
readelf -l payload.elf

# Check for executable segments
readelf -l payload.elf | grep -A 5 "LOAD"

# Identify stack permissions (look for RWE - bad sign)
readelf -l payload.elf | grep -i stack
```

### Section Headers
```bash
# List all sections
readelf -S payload.elf

# Check for suspicious sections
readelf -S payload.elf | grep -E "\.text|\.data|\.rodata|\.bss"

# Look for uncommon sections
readelf -S payload.elf | grep -v -E "\.text|\.data|\.rodata|\.bss|\.plt|\.got"
```

---

## 3. Binary Analysis Tools

### Using `objdump`
```bash
# Disassemble all executable sections
objdump -d payload.elf > disassembly.txt

# Show only .text section
objdump -d -j .text payload.elf

# Display all headers
objdump -x payload.elf

# Show dynamic symbols
objdump -T payload.elf

# Show file format
objdump -f payload.elf
```

### Using `strings` (Extract Readable Text)
```bash
# Basic strings extraction
strings payload.elf > strings.txt

# Minimum string length 6 characters
strings -n 6 payload.elf

# Look for IP addresses
strings payload.elf | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}'

# Look for URLs
strings payload.elf | grep -E 'http://|https://|ftp://'

# Look for commands
strings payload.elf | grep -E '/bin/|/usr/|/tmp/|/var/'

# Look for known malware indicators
strings payload.elf | grep -iE 'meterpreter|metasploit|payload|shell|reverse|bind'

# Search for function names
strings payload.elf | grep -E '^[a-zA-Z_][a-zA-Z0-9_]*$'
```

### Using `nm` (Symbol Table)
```bash
# List all symbols
nm payload.elf

# List dynamic symbols only
nm -D payload.elf

# Show only undefined symbols (imported functions)
nm -u payload.elf

# Show symbol types
nm -f sysv payload.elf
```

---

## 4. Dynamic Analysis Preparation (Static Review)

### Check Dependencies
```bash
# List shared library dependencies
ldd payload.elf

# WARNING: ldd executes the binary! Use safer alternative:
readelf -d payload.elf | grep NEEDED

# Or use objdump
objdump -p payload.elf | grep NEEDED
```

### Check for Packing/Obfuscation
```bash
# Check entropy (high entropy = packed/encrypted)
ent payload.elf

# Look for UPX packing
strings payload.elf | grep -i upx

# Check section sizes (very small .text = likely packed)
readelf -S payload.elf | awk '{print $3, $6}' | sort -k2 -n

# Detect packing with detect-it-easy
die payload.elf
```

### Identify System Calls
```bash
# Extract syscall instructions
objdump -d payload.elf | grep -E "syscall|int.*0x80"

# Count syscalls
objdump -d payload.elf | grep -c syscall

# Find specific dangerous syscalls
objdump -d payload.elf | grep -B 5 syscall | grep -E "mov.*eax|mov.*rax"
```

---

## 5. Automated Analysis Script

```bash
#!/bin/bash
# elf-analyzer.sh - Comprehensive ELF static analysis

ELF_FILE="$1"

if [[ ! -f "$ELF_FILE" ]]; then
    echo "Usage: $0 <elf_file>"
    exit 1
fi

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           ELF Static Analysis Report                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

echo "=== File Information ==="
echo "File: $ELF_FILE"
echo "Type: $(file -b "$ELF_FILE")"
echo "Size: $(stat -c%s "$ELF_FILE") bytes ($(du -h "$ELF_FILE" | awk '{print $1}'))"
echo

echo "=== File Hashes ==="
echo "MD5:    $(md5sum "$ELF_FILE" | awk '{print $1}')"
echo "SHA1:   $(sha1sum "$ELF_FILE" | awk '{print $1}')"
echo "SHA256: $(sha256sum "$ELF_FILE" | awk '{print $1}')"
if command -v ssdeep &>/dev/null; then
    echo "SSDEEP: $(ssdeep -b "$ELF_FILE" | tail -n1 | awk '{print $1}')"
fi
echo

echo "=== Timestamps ==="
stat -c 'Created:  %w
Modified: %y
Accessed: %x' "$ELF_FILE"
echo

echo "=== ELF Header ==="
readelf -h "$ELF_FILE" | grep -E "Class|Data|Type|Machine|Entry point"
echo

echo "=== Architecture & Format ==="
ARCH=$(readelf -h "$ELF_FILE" | grep Machine | awk -F: '{print $2}' | xargs)
CLASS=$(readelf -h "$ELF_FILE" | grep Class | awk '{print $2}')
echo "Architecture: $ARCH"
echo "Class: $CLASS"
echo

echo "=== Program Headers (Segments) ==="
readelf -l "$ELF_FILE" | grep -A 1 LOAD | head -n 6
echo

echo "=== Sections ==="
readelf -S "$ELF_FILE" | grep -E "\.text|\.data|\.rodata|\.bss" | \
    awk '{printf "%-15s %10s bytes\n", $2, "0x"$6}'
echo

echo "=== Dynamic Dependencies ==="
if readelf -d "$ELF_FILE" 2>/dev/null | grep -q NEEDED; then
    readelf -d "$ELF_FILE" | grep NEEDED | awk '{print $5}' | tr -d '[]'
else
    echo "Statically linked (no dependencies)"
fi
echo

echo "=== Imported Functions ==="
if nm -D "$ELF_FILE" 2>/dev/null | grep -q "U "; then
    nm -D "$ELF_FILE" 2>/dev/null | grep "U " | awk '{print $2}' | head -n 10
    echo "... (showing first 10)"
else
    echo "No dynamic symbols found"
fi
echo

echo "=== Suspicious Strings ==="
echo "IP Addresses:"
strings "$ELF_FILE" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 5
echo
echo "URLs:"
strings "$ELF_FILE" | grep -E 'http://|https://' | head -n 5
echo
echo "System Paths:"
strings "$ELF_FILE" | grep -E '^/[a-z]+/' | head -n 5
echo
echo "Potential Malware Indicators:"
strings "$ELF_FILE" | grep -iE 'meterpreter|metasploit|payload|shell|exec|socket' | head -n 5
echo

echo "=== Security Features ==="
if readelf -l "$ELF_FILE" 2>/dev/null | grep -q "GNU_STACK"; then
    STACK=$(readelf -l "$ELF_FILE" | grep GNU_STACK | awk '{print $7}')
    echo "Stack: $STACK"
    if [[ "$STACK" == *"E"* ]]; then
        echo "  ⚠️  WARNING: Executable stack detected!"
    fi
fi

if readelf -d "$ELF_FILE" 2>/dev/null | grep -q "BIND_NOW"; then
    echo "RELRO: Full"
else
    echo "RELRO: Partial or None"
fi

if objdump -d "$ELF_FILE" 2>/dev/null | grep -q "call.*@plt"; then
    echo "PIE: Enabled"
else
    echo "PIE: Disabled"
fi
echo

echo "=== System Calls ==="
SYSCALL_COUNT=$(objdump -d "$ELF_FILE" 2>/dev/null | grep -c "syscall\|int.*0x80")
echo "Total syscall instructions: $SYSCALL_COUNT"
echo

echo "=== Entropy Analysis ==="
if command -v ent &>/dev/null; then
    ENTROPY=$(ent "$ELF_FILE" | grep Entropy | awk '{print $3}')
    echo "Entropy: $ENTROPY"
    if (( $(echo "$ENTROPY > 7.5" | bc -l) )); then
        echo "  ⚠️  HIGH ENTROPY - Likely packed/encrypted"
    fi
fi
echo

echo "=== Entry Point ==="
ENTRY=$(readelf -h "$ELF_FILE" | grep "Entry point" | awk '{print $4}')
echo "Entry point address: $ENTRY"
echo

echo "=== File Permissions ==="
PERMS=$(stat -c '%A (%a)' "$ELF_FILE")
echo "Permissions: $PERMS"
if [[ "$PERMS" == *"x"* ]]; then
    echo "  ⚠️  File is executable"
fi
echo

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    Analysis Complete                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Save strings to file
strings "$ELF_FILE" > "${ELF_FILE}_strings.txt"
echo
echo "Strings extracted to: ${ELF_FILE}_strings.txt"
```

### Usage:
```bash
chmod +x elf-analyzer.sh
./elf-analyzer.sh payload.elf
```

---

## 6. Advanced Analysis Tools

### Radare2 (Reverse Engineering Framework)
```bash
# Install radare2
sudo apt install radare2

# Basic analysis
r2 -A payload.elf

# Inside r2:
# aaa      - Analyze all
# pdf @main - Disassemble main function
# iz       - List strings in data sections
# ii       - List imports
# ie       - List entrypoints
# afl      - List all functions
# s main; pdf - Seek to main and disassemble
# q        - Quit
```

### Ghidra (NSA's Reverse Engineering Tool)
```bash
# Download from: https://ghidra-sre.org/
# Run Ghidra and import the ELF file
# Let it auto-analyze
# Review:
# - Symbol Tree
# - Decompiler output
# - String references
# - Function call graphs
```

### Binary Ninja / IDA Free
```bash
# Commercial tools with free versions
# Excellent for disassembly and decompilation
# Better function recognition than basic tools
```

### LIEF (Library to Instrument Executable Formats)
```bash
pip3 install lief

python3 << EOF
import lief
binary = lief.parse("payload.elf")

print("Architecture:", binary.header.machine_type)
print("Entry point:", hex(binary.entrypoint))
print("Sections:")
for section in binary.sections:
    print(f"  {section.name}: {section.size} bytes")
    
print("\nImported functions:")
for func in binary.imported_functions:
    print(f"  {func.name}")
EOF
```

---

## 7. msfvenom Payload Specific Analysis

### Identify msfvenom Signatures
```bash
# Common msfvenom strings
strings payload.elf | grep -iE 'metasploit|meterpreter|msf|payload'

# Look for Metasploit User-Agent
strings payload.elf | grep -i "Mozilla"

# Check for common msfvenom shellcode patterns
xxd payload.elf | grep -E "31c0|31db|31c9|31d2|b0"

# Look for socket operations (reverse shell indicators)
strings payload.elf | grep -iE 'socket|connect|bind|listen|accept'
objdump -d payload.elf | grep -E "socket|connect" -A 5
```

### Extract Embedded Configuration
```bash
# Look for IP addresses (LHOST)
strings payload.elf | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# Look for ports (LPORT) - common: 4444, 4445, 8080
strings payload.elf | grep -oE ':[0-9]{4,5}|[0-9]{4,5}'

# Extract all hexadecimal patterns (might contain encoded IPs/ports)
strings payload.elf | grep -oE '0x[0-9a-fA-F]+'
```

### Network Indicators
```bash
# Search for IP in hex format (e.g., 192.168.1.10 = C0A8010A)
xxd payload.elf | grep -iE "c0a8|0a00|7f00"

# Look for common ports in hex
# 4444 = 0x115C, 8080 = 0x1F90
xxd payload.elf | grep -iE "115c|1f90|01bb"
```

---

## 8. Comparison & Similarity Detection

### Compare Multiple Samples
```bash
# Using ssdeep for fuzzy hashing
ssdeep payload1.elf payload2.elf payload3.elf > hashes.txt
ssdeep -m hashes.txt -r /path/to/samples/

# Binary diff
diff <(xxd payload1.elf) <(xxd payload2.elf) | head -n 50

# Using radiff2
radiff2 payload1.elf payload2.elf
```

### VirusTotal / Malware Databases
```bash
# Submit hash to VirusTotal (never upload the actual file if sensitive)
SHA256=$(sha256sum payload.elf | awk '{print $1}')
curl -s "https://www.virustotal.com/api/v3/files/$SHA256" \
  -H "x-apikey: YOUR_API_KEY" | jq

# Check against known malware databases
# - VirusTotal
# - Hybrid Analysis
# - ANY.RUN
# - Joe Sandbox
```

---

## 9. Quick Reference Commands

```bash
# One-liner for quick analysis
echo "=== Quick ELF Analysis ===" && \
  echo "Hash: $(sha256sum payload.elf | awk '{print $1}')" && \
  echo "Type: $(file -b payload.elf)" && \
  echo "Arch: $(readelf -h payload.elf | grep Machine | awk -F: '{print $2}')" && \
  echo "IPs: $(strings payload.elf | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')" && \
  echo "URLs: $(strings payload.elf | grep -E 'http://' | head -n 3)"
```

---

## 10. Safety Reminders

- **Never execute** suspicious binaries outside isolated VMs
- **Always snapshot** your analysis VM before starting
- **Disable network** on analysis VM or use fake network
- **Use Linux namespaces** or containers for extra isolation
- **Document everything** - hashes, timestamps, observations
- **Report findings** to appropriate authorities if malicious

---

## Output Example

```
File: payload.elf
SHA256: a1b2c3d4e5f6...
Type: ELF 64-bit LSB executable, x86-64
Size: 73728 bytes
Architecture: x86-64
Entry Point: 0x400080
Statically Linked: Yes

Suspicious Indicators:
- IP Address found: 192.168.1.100
- Port found: 4444
- No executable stack
- Calls socket(), connect()
- String "meterpreter" found

Conclusion: Likely msfvenom linux/x64/meterpreter/reverse_tcp payload
```