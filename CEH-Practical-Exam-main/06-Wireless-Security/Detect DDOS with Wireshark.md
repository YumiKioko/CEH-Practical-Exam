# Detecting a DDoS Attack Using Wireshark


---

## 📌 What Is a DDoS Attack?

A **Distributed Denial of Service (DDoS)** attack is an attempt to overwhelm a target system, service, or network with massive traffic from multiple sources, making it unavailable to legitimate users.

### Common Types of DDoS:
- **SYN Flood** – floods with TCP connection requests.
- **UDP Flood** – sends massive amounts of UDP packets.
- **ICMP Flood (Ping flood)** – overwhelms with echo requests.
- **DNS Amplification** – exploits DNS servers to flood a victim.
- **HTTP Flood** – sends a high volume of HTTP requests.

---

## Recognizing Signs of DDoS in Wireshark

### 🚩 General Symptoms:
- Unusual spikes in traffic.
- Many packets per second targeting the same IP.
- Requests from hundreds or thousands of IPs.
- High traffic on one specific protocol (e.g., TCP SYNs, ICMP, DNS).

---

## Wireshark Filters for DDoS Detection

Use these display filters in Wireshark to narrow down traffic and identify suspicious behavior.

---

### 1. **SYN Flood Detection**

Filter:
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

What to look for:

- Massive SYN packets with no corresponding ACKs.
    
- Same destination port repeatedly (e.g., port 80 or 443).
    
- High volume from different source IPs.
    

---

### 2. **UDP Flood Detection**

Filter:
```
udp
```

Optional: For a specific service (e.g., DNS):

Filter:
```
udp.port == 53
```

What to look for:

- Thousands of UDP packets in a short timeframe.
    
- Many different source IPs targeting one destination.

### 3. **ICMP (Ping) Flood Detection**

Filter:
```
icmp.type == 8
```

What to look for:

- Many ICMP Echo Requests with little or no replies.
    
- High frequency over a short time.

### 4. **Single IP Targeting (Victim Focused)**

Filter to show all traffic targeting a specific IP:
```
ip.dst == <victim-ip>
```

Combine with protocol filter:
```
ip.dst == <victim-ip> and tcp.flags.syn == 1
```

---

## Example Workflow: Detecting SYN Flood

1. Open Wireshark and load your capture or begin live capture.
    
2. Apply filter:
```
   tcp.flags.syn == 1 and tcp.flags.ack == 0 
```

Go to Statistics > Conversations → TCP tab.

Sort by "Packets" or "Bytes".

Identify one or more IPs sending massive SYN packets to one destination.

## Tips

- Enable name resolution (`View > Name Resolution`) for readability.
    
- Use color rules to highlight suspicious packet types.
    
- Capture on the correct interface (e.g., WAN or edge device).
  














































