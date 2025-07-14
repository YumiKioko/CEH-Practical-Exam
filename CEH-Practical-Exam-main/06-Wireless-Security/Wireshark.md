 
## 🚀 Installation

  ### Debian/Ubuntu:

  ```bash

sudo apt install wireshark

```

### RedHat/CentOS:

  ```bash

sudo dnf install wireshark-gtk

```

### macOS:
  
```bash

brew install wireshark

```


---

## 🖥️ Starting Wireshark

  

- GUI: Just run `wireshark`

- TUI (terminal): Use `tshark`

  
```bash

sudo wireshark

```

  
---

## 🎯 Capture Filters vs Display Filters

  

| Type | Purpose | Example |

|------|---------|---------|

| **Capture Filter** | Before packet capture | `tcp port 80` |

| **Display Filter** | After capture (analysis) | `http.request.method == "GET"` |

  

---

## 🎛️ Common Capture Filters

  
```bash

host 192.168.1.1           # Traffic to/from host

net 192.168.1.0/24         # Traffic in subnet

port 443                   # All HTTPS traffic

tcp                        # All TCP packets

udp port 53                # DNS queries

not arp                    # Ignore ARP

```


---
## 🔍 Common Display Filters

### Protocols:

```bash

http

dns

tcp

icmp

ftp

ssl || tls

```

### IP Address Filtering:

```bash

ip.addr == 10.0.0.1

ip.src == 192.168.1.5

ip.dst == 8.8.8.8

```

### TCP:

```bash

tcp.port == 80

tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN packets

tcp.analysis.retransmission

```

### HTTP:

```bash

http.request.method == "GET"

http.host == "example.com"

http.set_cookie

http.authorization

```

### DNS:

```bash

dns.qry.name == "google.com"

dns.flags.rcode != 0

```

### Credentials:

```bash

ftp.request.command == "PASS"

http.authorization

```

---
## 📂 Follow Streams

### Follow TCP stream:

- Right-click on a TCP packet → "Follow" → "TCP Stream"

### Useful for:

- Viewing HTTP requests

- Extracting credentials or file transfers

- Analyzing full conversations

---

## 📈 Analyze → Protocol Hierarchy

View breakdown of all captured protocols and their percentage.

---
## 📤 Export Objects

**File → Export Objects → HTTP / SMB / DICOM / TFTP**

Used to extract files transferred over the network.

---
## 🛠 Useful Features

- **Color Rules**: Highlight packets by protocol or flag

- **Statistics → Conversations**: Analyze flows between hosts

- **Name Resolution**: Resolve IPs to hostnames

  - `View → Name Resolution → Enable for MAC/DNS`

---
## 🧰 Command-Line (tshark)

```bash

sudo tshark -i wlan0 -f "port 80" -w capture.pcap

```
### Display with filter:

```bash

tshark -r capture.pcap -Y "http"

```

---
### 🧪 Packet Dissection Example

```http

GET /index.html HTTP/1.1

Host: vulnerable.site

Authorization: Basic dXNlcjpwYXNz

```

- `Authorization` header = base64 → credentials

- `Follow TCP Stream` shows entire HTTP conversation

---
## 🧱 Pro Tips

- Use filters to reduce noise (especially `ip.addr`, `http`, `dns`)

- Use color coding to spot anomalies

- Use `tshark` for automation or scripting

---
