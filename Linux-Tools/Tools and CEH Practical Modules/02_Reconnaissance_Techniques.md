# 02 - Reconnaissance Techniques (Footprinting & Reconnaissance / Scanning / Enumeration)

**Purpose:** Passive and active info gathering to build an attack surface map.

**Tools mapped from your list:**
- `whois` — domain registrant, registrar, creation/expiry info.  
  Example: `whois example.com`
- `nslookup`, `dig` — DNS queries and record inspection.  
  Examples: `nslookup -type=MX example.com`, `dig @8.8.8.8 example.com ANY +short`
- `dnsdumpster` — web-based DNS/subdomain mapping and infrastructure graphing.
- `traceroute` — network path discovery. `traceroute example.com`
- `ping`, `fping` — host reachability and fast ping sweeps (`fping -g 10.0.0.0/24`)
- `gobuster`, `ffuf` — directory / file / vhost brute-force (enumeration).  
  Example: `gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt`
- `wpscan` — WordPress reconnaissance (enumerate versions, plugins, users).  
  Example: `wpscan --url https://target -e vp,vt,cb,u`
- `whois`, `nslookup`, `dig`, `dnsdumpster` often used together for DNS/registrant mapping.

**Added recommended recon tools:**
- `nmap` (host discovery & port/service discovery) — `nmap -sS -Pn -A target`.
- `theHarvester` (email/subdomain harvesting), `Amass` (advanced subdomain enumeration).

**Notes:** Recon is heavy on passive tools first (OSINT) then active enumeration as allowed by scope.