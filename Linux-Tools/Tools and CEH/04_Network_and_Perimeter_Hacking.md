# 04 - Network & Perimeter Hacking (Sniffing / Social Engineering / DoS / Session Hijacking / Evading IDS)

**Purpose:** Attack the network, intercept traffic, brute-force services, and evade detection.

**Tools mapped from your list:**
- `aircrack-ng` (also Wireless module) — capture/WEP/WPA handshakes and crack PSKs.  
  Example high-level flow: `airodump-ng` → `aireplay-ng` → `aircrack-ng`
- `netcat` — pivoting, banner grabbing, and tunneling.
- `hydra` — credential brute forcing against network services.
- `fping`, `ping`, `traceroute` — network reachability & topology checks.
- `whois` — identify external contact points for social-engineering context.

**Added recommended network/perimeter tools:**
- `Wireshark` / `tcpdump` — deep packet capture & analysis
- `ettercap` — MITM and ARP poisoning (session hijacking)
- `hping3` / `nping` — craft custom packets and DoS testing (controlled and in scope)
- `iptables` rules knowledge & log analysis to demonstrate IDS evasion awareness

**Examples:**
```bash
# quick ping sweep with fping
fping -a -g 10.0.0.1 10.0.0.254
# capture with tcpdump
tcpdump -i eth0 -w capture.pcap
```

**Ethics note:** DoS and MITM are destructive — never run in a live/production environment unless explicitly allowed.