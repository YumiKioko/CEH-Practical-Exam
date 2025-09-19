# Feroxbuster

**Description:**  
Feroxbuster is a fast, multi-threaded content discovery tool for directories and files.

**Basic Syntax:**
```bash
feroxbuster -u https://target -w /path/wordlist
```

**Common Options:**
- `-t` — threads  
- `-x` — extensions to append  
- `-r` — follow redirects

**Example:**
```bash
feroxbuster -u https://target -w /usr/share/wordlists/common.txt -t 50
```