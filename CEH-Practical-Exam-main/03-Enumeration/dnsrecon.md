Command Used: #dns_recon

```
dnsrecon -t brt -d acmeitsupport.th
```

Explanation of Flags:

-t brt: Specifies the brute-force enumeration technique.

-d acmeitsupport.th: Target domain for the enumeration.

Objective: To identify valid subdomains of acmeitsupport.th that may not be visible through passive reconnaissance methods.

Standard Enumeration:

```
dnsrecon -d acmeitsupport.th
```

Performs standard DNS queries including SOA, NS, MX, A, and AAAA records.

Zone Transfer Check (AXFR):

dnsrecon -t axfr -d acmeitsupport.th
Attempts a DNS zone transfer, which could disclose all DNS records if misconfigured.

Google Dorking for Subdomains:

```
dnsrecon -t google -d acmeitsupport.th
```

Uses Google search engine to discover subdomains.

Bing Search for Subdomains:

```
dnsrecon -t bing -d acmeitsupport.th
```

Performs subdomain enumeration using Bing.

Reverse Lookup:

```
dnsrecon -r <startIP>-<endIP> -n <nameserver>
```

Discovers hostnames by reverse resolving IP ranges.

DNS Cache Snooping:

```
dnsrecon -t snoop -d acmeitsupport.th -n <nameserver>
```

Tests if a DNS server has cached specific entries, which may indicate recent access.

Wildcard Detection:

```
dnsrecon -w -d acmeitsupport.th
```

Detects wildcard DNS records that may lead to false positives in brute-force results.