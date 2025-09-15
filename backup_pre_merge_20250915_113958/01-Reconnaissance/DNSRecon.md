The following command utilizes `dnsrecon`, a widely used DNS enumeration tool, to perform brute-force subdomain discovery against the domain `acmeitsupport.th`. This can help uncover additional attack surfaces such as staging environments, VPN gateways, email servers, and more.

**Command Used:** #dns_recon

```bash
dnsrecon -t brt -d acmeitsupport.th
```


**Explanation of Flags:**

- `-t brt`: Specifies the brute-force enumeration technique.
- `-d acmeitsupport.th`: Target domain for the enumeration.

**Objective:** To identify valid subdomains of `acmeitsupport.th` that may not be visible through passive reconnaissance methods.

**Use Cases:**

- Mapping the organization's attack surface.
- Identifying potentially misconfigured or forgotten services.
- Feeding results into further enumeration or exploitation tools.  

**Other Useful Techniques with dnsrecon:**

1. **Standard Enumeration:**

```
dnsrecon -d acmeitsupport.th
```

    Performs standard DNS queries including SOA, NS, MX, A, and AAAA records.

2. **Zone Transfer Check (AXFR):**

```
dnsrecon -t axfr -d acmeitsupport.th
```

    Attempts a DNS zone transfer, which could disclose all DNS records if misconfigured.

3. **Google Dorking for Subdomains:**

```
dnsrecon -t google -d acmeitsupport.th
```

    Uses Google search engine to discover subdomains.

4. **Bing Search for Subdomains:**

```
dnsrecon -t bing -d acmeitsupport.th
```

    Performs subdomain enumeration using Bing.

5. **Reverse Lookup:**

```
dnsrecon -r <startIP>-<endIP> -n <nameserver>
```

    Discovers hostnames by reverse resolving IP ranges.

6. **DNS Cache Snooping:**

```
dnsrecon -t snoop -d acmeitsupport.th -n <nameserver>
```

    Tests if a DNS server has cached specific entries, which may indicate recent access.

7. **Wildcard Detection:**

```
dnsrecon -w -d acmeitsupport.th
```

    Detects wildcard DNS records that may lead to false positives in brute-force results.