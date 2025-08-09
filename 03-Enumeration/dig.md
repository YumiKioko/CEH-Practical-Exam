## Basic Query

```
dig example.com
```

Query Specific Record Types

```
dig example.com A      # IPv4 address
```

```
dig example.com AAAA   # IPv6 address
```

```
dig example.com MX     # Mail servers
```

```
dig example.com NS     # Name servers
```

```
dig example.com TXT    # Text records
```

```
dig example.com CNAME  # Canonical name
```

## Reverse DNS Lookup

```
dig -x 8.8.8.8
```

## Use a Specific DNS Server

```
dig @1.1.1.1 example.com
```

## Short Answer Only

```
dig +trace example.com
```

## Trace DNS Resolution Path

```
dig +trace example.com
```

## Output in a Script-Friendly Format

```
dig +noall +answer example.com
```

## Query DNS Over TCP

```
dig +tcp example.com
```
