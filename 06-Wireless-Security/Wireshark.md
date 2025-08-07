## Starting Wireshark
 
- GUI: Just run `wireshark`

- TUI (terminal): Use `tshark`
 
```bash

sudo wireshark

```

---
## Capture Filters vs Display Filters

  
| Type | Purpose | Example |

|------|---------|---------|

| **Capture Filter** | Before packet capture | `tcp port 80` |

| **Display Filter** | After capture (analysis) | `http.request.method == "GET"` |

  

---

## Common Capture Filters

  
```bash

host 192.168.1.1           # Traffic to/from host

net 192.168.1.0/24         # Traffic in subnet

port 443                   # All HTTPS traffic

tcp                        # All TCP packets

udp port 53                # DNS queries

not arp                    # Ignore ARP

```


---
## Common Display Filters

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

