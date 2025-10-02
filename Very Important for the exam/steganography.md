# Steganography Analysis Cheat Sheet

**WARNING:** Only analyze files you own or have authorization to examine. Unauthorized access to hidden data may violate privacy laws.

---

## Part 1: General BMP/Image Steganography Analysis

### Quick Identification
```bash
# File type and basic info
file image.bmp
exiftool image.bmp

# File size (unusually large = suspicious)
ls -lh image.bmp
```

### 1. Metadata Analysis
```bash
# Extract all EXIF metadata
exiftool image.bmp
exiftool -a -G1 image.bmp  # Detailed output

# Check for comments/descriptions
exiftool -Comment -Description image.bmp

# Look for custom fields
exiftool -s image.bmp | grep -v "File\|Image\|JFIF"
```

### 2. Embedded File Detection
```bash
# Install binwalk
sudo apt install binwalk

# Scan for embedded files
binwalk image.bmp

# Auto-extract embedded files
binwalk -e image.bmp
# Creates _image.extracted/ folder

# Manually check for file signatures
xxd image.bmp | grep -E "PK\|Rar\|7z\|ZIP\|PDF\|JFIF"
```

### 3. LSB (Least Significant Bit) Analysis
```bash
# Install zsteg (best for BMP/PNG)
sudo apt install ruby
gem install zsteg

# Auto-detect LSB steganography
zsteg -a image.bmp

# Extract all possible LSB data
zsteg --all image.bmp > zsteg_output.txt

# Test specific bit planes
zsteg -E 'b1,r,lsb,xy' image.bmp  # Red channel, 1st bit
zsteg -E 'b1,g,lsb,xy' image.bmp  # Green channel
zsteg -E 'b1,b,lsb,xy' image.bmp  # Blue channel

# Test multiple bits
zsteg -E 'b1,rgb,lsb,xy' image.bmp  # All RGB
zsteg -E 'b2,rgb,lsb,xy' image.bmp  # 2 bits per channel
```

### 4. Steghide (Password-Protected)
```bash
# Install steghide
sudo apt install steghide

# Check if steghide was used
steghide info image.bmp

# Try to extract (will prompt for password)
steghide extract -sf image.bmp

# Extract with known password
steghide extract -sf image.bmp -p "password123"

# Brute force with wordlist
sudo apt install stegcracker
stegcracker image.bmp /usr/share/wordlists/rockyou.txt
stegcracker image.bmp custom_wordlist.txt
```

### 5. String Analysis (Filtered)
```bash
# Don't use raw strings - too much noise!
# Instead, filter intelligently:

# Look for readable text (min 10 chars)
strings -n 10 image.bmp | less

# Search for specific patterns
strings image.bmp | grep -E "flag|password|key|secret" -i
strings image.bmp | grep -E "BEGIN.*KEY|END.*KEY"  # PEM keys
strings image.bmp | grep -E "^[A-Za-z0-9+/]{40,}={0,2}$"  # Base64

# Look for URLs/IPs
strings image.bmp | grep -E "http://|https://|ftp://"
strings image.bmp | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# Search for hex patterns (hashes)
strings image.bmp | grep -E "^[0-9a-f]{32}$"  # MD5
strings image.bmp | grep -E "^[0-9a-f]{40}$"  # SHA1
strings image.bmp | grep -E "^[0-9a-f]{64}$"  # SHA256
```

### 6. Visual Analysis
```bash
# Install tools
sudo apt install imagemagick gimp

# View LSB planes visually
convert image.bmp -depth 1 lsb_plane.bmp

# Extract color channels separately
convert image.bmp -channel R -separate red.bmp
convert image.bmp -channel G -separate green.bmp
convert image.bmp -channel B -separate blue.bmp

# Open in GIMP and adjust levels to see hidden data
gimp image.bmp
# Colors → Levels → Adjust to extreme values
```

### 7. Pixel Data Analysis
```bash
# Python script to analyze pixels
cat > analyze_pixels.py <<'EOF'
from PIL import Image
import sys

img = Image.open(sys.argv[1])
pixels = img.load()
width, height = img.size

print(f"Image: {width}x{height} pixels")

# Extract LSB from each channel
for channel_name, channel_idx in [('Red', 0), ('Green', 1), ('Blue', 2)]:
    bits = ''
    for y in range(min(height, 1000)):  # First 1000 rows
        for x in range(width):
            pixel = pixels[x, y]
            if isinstance(pixel, tuple) and len(pixel) >= 3:
                bits += str(pixel[channel_idx] & 1)
    
    # Try to decode as ASCII
    text = ''
    for i in range(0, len(bits)-8, 8):
        byte = bits[i:i+8]
        char_code = int(byte, 2)
        if 32 <= char_code <= 126:  # Printable ASCII
            text += chr(char_code)
        else:
            text += '.'
    
    print(f"\n{channel_name} channel LSB (first 500 chars):")
    print(text[:500])
EOF

python3 analyze_pixels.py image.bmp
```

### 8. Hex Analysis
```bash
# Look for data after image end
# BMP header is 54 bytes, then pixel data

# Check file structure
xxd image.bmp | head -n 10  # Header
xxd image.bmp | tail -n 50  # End of file (suspicious data?)

# Search for text markers at end
tail -c 10000 image.bmp | strings

# Calculate expected file size
# BMP size = 54 + (width * height * bytes_per_pixel)
# If actual size > expected = data appended
```

---

## Part 2: Finding Secrets with Known Pattern

### Pattern: Aaaaa*N*aaaN
- **A** = uppercase letter
- **a** = lowercase letter
- **N** = digit (0-9)
- **\*** = literal asterisk

Example: `HELLO*5*abc9`, `WORLD*3*xyz7`

### Method 1: Direct String Search
```bash
# Exact pattern match
strings image.bmp | grep -E '^[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]$'

# Pattern can appear anywhere in line
strings image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Case variations (if unsure)
strings image.bmp | grep -iE '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Save matches to file
strings image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]' > secrets_found.txt
```

### Method 2: Search in LSB Data
```bash
# Extract LSB and search
zsteg -E 'b1,r,lsb,xy' image.bmp | strings | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'
zsteg -E 'b1,g,lsb,xy' image.bmp | strings | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'
zsteg -E 'b1,b,lsb,xy' image.bmp | strings | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# All channels at once
zsteg -E 'b1,rgb,lsb,xy' image.bmp | strings | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Try all zsteg extractions
zsteg --all image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'
```

### Method 3: Python Script for Pattern Search
```bash
cat > find_pattern.py <<'EOF'
#!/usr/bin/env python3
import re
import sys

if len(sys.argv) < 2:
    print("Usage: ./find_pattern.py image.bmp")
    sys.exit(1)

filename = sys.argv[1]

# Read file as binary and try to decode
with open(filename, 'rb') as f:
    data = f.read()

# Try to decode as ASCII (ignore errors)
text = data.decode('ascii', errors='ignore')

# Pattern: 5 uppercase + * + digit + * + 3 lowercase + digit
pattern = r'[A-Z]{5}\*\d\*[a-z]{3}\d'

matches = re.findall(pattern, text)

if matches:
    print(f"Found {len(matches)} secret(s):")
    for i, match in enumerate(matches, 1):
        print(f"  {i}. {match}")
else:
    print("No secrets found with pattern Aaaaa*N*aaaN")

# Also search in hex representation
hex_text = data.hex()
# Convert pattern to hex and search
# (more complex, omitted for brevity)
EOF

chmod +x find_pattern.py
python3 find_pattern.py image.bmp
```

### Method 4: Search in All Extracted Data
```bash
# First extract everything possible
mkdir analysis
cd analysis

# Extract with binwalk
binwalk -e ../image.bmp

# Extract with zsteg
zsteg --all ../image.bmp > zsteg_all.txt

# Extract with steghide (try without password)
steghide extract -sf ../image.bmp -p "" 2>/dev/null || true

# Now search all extracted files
find . -type f -exec strings {} \; | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Search in specific files
grep -r -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]' .
```

### Method 5: Hexadecimal Pattern Search
```bash
# Convert pattern to hex and search
# A-Z = 41-5A in hex
# a-z = 61-7A in hex
# 0-9 = 30-39 in hex
# * = 2A in hex

# Search in hex dump
xxd image.bmp | grep "2a.*2a"  # Look for two asterisks

# More precise (harder to construct regex for hex)
xxd image.bmp > image.hex
# Manually inspect around asterisks (2a)
grep "2a" image.hex | less
```

### Method 6: Automated Full Scan Script
```bash
cat > full_scan.sh <<'EOF'
#!/bin/bash

IMAGE="$1"
PATTERN='[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

echo "=== Full Steganography Scan with Pattern Search ==="
echo "Image: $IMAGE"
echo "Pattern: Aaaaa*N*aaaN"
echo

echo "[1] Searching in raw strings..."
strings "$IMAGE" | grep -E "$PATTERN" && echo "✓ Found in strings!" || echo "✗ Not in strings"
echo

echo "[2] Searching in metadata..."
exiftool "$IMAGE" | grep -E "$PATTERN" && echo "✓ Found in metadata!" || echo "✗ Not in metadata"
echo

echo "[3] Searching in binwalk extraction..."
binwalk -e "$IMAGE" 2>/dev/null
if [ -d "_${IMAGE}.extracted" ]; then
    find "_${IMAGE}.extracted" -type f -exec strings {} \; | grep -E "$PATTERN" && echo "✓ Found in embedded files!" || echo "✗ Not in embedded files"
fi
echo

echo "[4] Searching in zsteg LSB..."
for method in "b1,r,lsb,xy" "b1,g,lsb,xy" "b1,b,lsb,xy" "b1,rgb,lsb,xy"; do
    result=$(zsteg -E "$method" "$IMAGE" 2>/dev/null | strings | grep -E "$PATTERN")
    if [ -n "$result" ]; then
        echo "✓ Found in LSB ($method): $result"
    fi
done
echo

echo "[5] Trying steghide without password..."
steghide extract -sf "$IMAGE" -p "" 2>/dev/null && \
    strings "${IMAGE}.out" 2>/dev/null | grep -E "$PATTERN" && \
    echo "✓ Found in steghide data!" || echo "✗ Steghide failed or no match"
echo

echo "=== Scan Complete ==="
EOF

chmod +x full_scan.sh
./full_scan.sh image.bmp
```

---

## Common Steganography Tools Reference

| Tool | Purpose | Best For |
|------|---------|----------|
| **steghide** | Hide/extract data with password | General purpose, password-protected |
| **zsteg** | LSB analysis | BMP, PNG automatic detection |
| **stegsolve** | Visual analysis | Viewing bit planes, filters |
| **binwalk** | Find embedded files | Archives, executables in images |
| **exiftool** | Metadata extraction | Comments, custom EXIF fields |
| **stegcracker** | Brute force steghide | Password cracking |
| **outguess** | Statistical stego | JPEG files |
| **jsteg** | JPEG steganography | JPEG LSB |
| **strings** | Extract text | Quick text search |

---

## Quick Reference Commands

```bash
# One-liner for pattern search
strings image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# One-liner full extraction + search
(strings image.bmp; zsteg --all image.bmp; binwalk -e image.bmp) | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Quick LSB check with pattern
zsteg -a image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# Extract everything and grep recursively
binwalk -e image.bmp && grep -r '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]' _image.bmp.extracted/
```

---

## Troubleshooting

### "Nothing found with strings"
- Data is in LSB → use `zsteg`
- Data is compressed → use `binwalk`
- Data is encrypted → use `steghide` with password

### "zsteg finds nothing"
- Try other tools: `steghide`, `binwalk`
- Check metadata: `exiftool`
- Try visual analysis: `stegsolve`

### "Pattern not matching"
- Verify pattern format is correct
- Try case-insensitive search: `grep -i`
- Search in all extracted data, not just original file
- Data might be encoded (base64, hex)

### "Too many false positives"
- Increase minimum string length: `strings -n 15`
- Add context to pattern (if you know more)
- Search only in specific sections of file

---

## Android ADB File Analysis Workflow

Since you pulled from Android via ADB:

```bash
# 1. Verify file integrity
md5sum image.bmp
sha256sum image.bmp

# 2. Check if file was modified on device
exiftool image.bmp | grep -i "modify\|create\|date"

# 3. Look for Android app signatures
strings image.bmp | grep -i "android\|com\."

# 4. Run full steganography scan
./full_scan.sh image.bmp

# 5. If found, document everything
echo "Found: $(strings image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]')" > findings.txt
```

---

## Final Tips

1. **Always try multiple methods** - don't rely on just `strings`
2. **LSB is most common** in BMP files - use `zsteg` first
3. **Pattern matching** is powerful when you know the format
4. **Document your findings** - save all outputs
5. **Legal reminder**: Only analyze files you own or have permission to examine

---

## Summary for Your Case

```bash
# Since you know the pattern Aaaaa*N*aaaN:

# Quick test:
strings image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# If not found, try LSB:
zsteg -a image.bmp | grep -E '[A-Z]{5}\*[0-9]\*[a-z]{3}[0-9]'

# If still not found, full scan:
./full_scan.sh image.bmp
```

The pattern format gives you a **huge advantage** - you can filter the 3200 lines down to just matching lines!