# Amass

**Description:**  
Amass performs DNS enumeration and subdomain discovery using passive and active techniques.

**Basic Syntax:**
```bash
amass enum -d example.com
```

**Common Options:**
- `-passive` — passive-only enumeration  
- `-src` — show source of findings  
- `-o` — output file

**Examples:**
```bash
amass enum -d example.com -o amass.txt
amass enum -passive -d example.com -src
```