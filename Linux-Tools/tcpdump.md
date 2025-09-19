# Tcpdump

**Description:**  
Tcpdump is a command-line packet capture tool used to capture and filter network traffic.

**Basic Syntax:**
```bash
tcpdump -i <interface> [expression] -w file.pcap
```

**Common Examples:**
- Capture all traffic on interface: `tcpdump -i eth0 -w capture.pcap`  
- Capture only HTTP: `tcpdump -i eth0 tcp port 80 -w http.pcap`  
- Read pcap: `tcpdump -r capture.pcap -nn -vv`

**Filters use BPF syntax:** e.g., `host 10.0.0.1 and port 443`