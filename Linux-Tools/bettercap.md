# Bettercap

**Description:**  
Bettercap is a powerful, modular network attack framework for MITM, DNS spoofing, etc.

**Basic Usage:**
```bash
bettercap -iface wlan0
```

**Examples:**
```bash
# start interactive session then enable modules
bettercap -iface eth0
> net.probe on
> net.sniff on
> net.recon on
```