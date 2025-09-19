# Reaver

**Description:**  
Reaver targets WPS (Wi‑Fi Protected Setup) registrar implementations to recover WPA/WPA2 passphrases.

**Basic Syntax:**
```bash
reaver -i wlan0mon -b <BSSID> -c <channel> -vv
```

**Notes:**  
- Can be slow; many routers rate-limit or block WPS attempts. Use only in lab/scope.