# Dig

**Description:**\
`dig` (Domain Information Groper) queries DNS servers for information
about host addresses, mail exchanges, nameservers, etc.

**Basic Syntax:**

``` bash
dig [@server] name [type]
```

**Common Options:** - `+short` -- Simplified output\
- `+trace` -- Trace the delegation path\
- `+noall +answer` -- Show only answer section\
- `ANY` -- Get all records

**Use Cases:** - DNS troubleshooting\
- View DNS record types (A, MX, TXT, etc.)\
- Trace DNS resolution path

**Examples:**

``` bash
dig google.com
dig google.com MX
dig @8.8.8.8 google.com A +short
dig +trace google.com
```
