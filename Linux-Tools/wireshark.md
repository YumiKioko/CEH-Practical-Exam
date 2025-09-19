# Wireshark

**Description:**  
Wireshark is a GUI packet analyzer for inspecting network traffic and protocols.

**Basic Usage:**
- Start capture on an interface (GUI) or use `dumpcap/tshark` for CLI.
- Use display filters to inspect packets (e.g., `http`, `tcp.port == 80`, `ip.addr == 10.0.0.1`).

**Common Display Filters:**
- `ip.addr == 10.0.0.1`  
- `tcp.port == 443`  
- `http` / `dns` / `ssl` / `smtp`

**Use Cases:**
- Deep packet inspection, protocol debugging, extracting files from traffic

**CLI alternative (tshark):**
```bash
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -Y "http && ip.addr==10.0.0.1"
```