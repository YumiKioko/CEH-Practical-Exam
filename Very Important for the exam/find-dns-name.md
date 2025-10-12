# Identify DNS Server Name from an IP (Parrot OS)

A concise workflow and exact commands to identify a DNS/server name when you only have an IP address, tailored for **Parrot OS** (Debian-based pentest distro).

---

## Quick recommended order
1. Reverse DNS (PTR) lookup  
2. NetBIOS / SMB enumeration  
3. Query the IP as a DNS server (SOA / reverse via that server)  
4. Service & banner scanning (nmap)  
5. LDAP / Active Directory queries (if applicable)

---

## 1) Reverse DNS (PTR) — first and simplest
```bash
dig -x <IP> +short
# or
host <IP>
```
If a PTR record exists you’ll get a hostname (e.g. `dns01.example.com.`). If nothing returns, PTR might not be configured.

---

## 2) NetBIOS / SMB (Windows name advertising)
Useful for Windows servers that advertise NetBIOS/SMB names.
```bash
nbtscan <IP>
# or
nmblookup -A <IP>

# If SMB is open:
smbclient -L //<IP> -N
```
`nbtscan` / `nmblookup` and `smbclient` can reveal NetBIOS names or server banners.

---

## 3) Query the IP as a DNS server
If the IP is a DNS server, ask it directly:
```bash
dig @<IP> soa .
dig @<IP> -x <IP> +short
dig @<IP> -t any <your-zone>
```
Check the SOA record — the **MNAME** field often gives the primary DNS server name. Zone transfers (`AXFR`) will likely be blocked unless misconfigured.

---

## 4) Service & Banner Scanning (nmap)
If PTR & NetBIOS fail, check open services and banners:
```bash
nmap -sV -p 53,88,135,139,389,445,3268,3269 <IP>
nmap -sV --script=banner -p 389,445,53 <IP>
```
Look for:
- `53` (DNS) — may reveal service/banners.  
- `445` (SMB) — often contains host/NetBIOS names.  
- `389` (LDAP) — may show AD/domain info.

> **Note:** Only scan networks you own or are authorized to test.

---

## 5) LDAP / AD-aware checks (if it’s a Domain Controller)
If LDAP is open and accessible:
```bash
# anonymous or simple bind (if allowed)
ldapsearch -x -H ldap://<IP> -s base namingcontexts

# or query for domain controller info using ldapsearch
ldapsearch -x -H ldap://<IP> -b "" -s base "(objectClass=*)" namingContexts
```
If you have domain credentials, AD PowerShell commands (from a Windows host) can map IP → AD objects:
```powershell
Get-ADDomainController -Filter * | Where-Object {$_.IPv4Address -eq "<IP>"}
```

---

## Practical workflow (one-liner order)
```bash
dig -x <IP> +short || nmblookup -A <IP> || dig @<IP> -x <IP> +short || nmap -sV -p 53,389,445 <IP>
```

---

## Caveats & gotchas
- **No PTR configured:** Reverse lookups may fail.  
- **Internal-only names:** FQDNs may only resolve inside the corporate network.  
- **Firewalls / blocked ports:** UDP/53, SMB, LDAP may be filtered.  
- **Multiple names / NAT:** IP → name may be ambiguous.  
- **Permissions:** AD/DHCP queries require credentials.

---

## Parrot-recommended order (summary)
`dig -x` → `nbtscan` / `nmblookup` → `dig @IP soa` → `nmap -sV` → `ldapsearch` / AD queries

---

## Example: run on Parrot
```bash
# 1) PTR
dig -x 10.0.0.5 +short

# 2) NetBIOS / SMB
nmblookup -A 10.0.0.5
smbclient -L //10.0.0.5 -N

# 3) Query DNS server
dig @10.0.0.5 soa .
dig @10.0.0.5 -x 10.0.0.5 +short

# 4) nmap banners
nmap -sV --script=banner -p 53,389,445 10.0.0.5

# 5) ldapsearch (if LDAP open)
ldapsearch -x -H ldap://10.0.0.5 -s base namingcontexts
```

---

**Reminder:** Only perform these actions on networks and hosts you are authorized to test.
