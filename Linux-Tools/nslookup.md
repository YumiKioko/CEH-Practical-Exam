# Nslookup

**Description:**\
`nslookup` queries DNS servers interactively or non-interactively.

**Basic Syntax:**

``` bash
nslookup [options] [domain]
```

**Interactive Mode:**

``` bash
nslookup
> server 8.8.8.8
> set type=MX
> google.com
```

**Common Options:** - `set type=A` -- Query IPv4 records\
- `set type=MX` -- Query mail servers\
- `set type=NS` -- Query nameservers\
- `set type=TXT` -- Query TXT records

**Use Cases:** - Test DNS resolution\
- Identify mail servers and NS records\
- Debug DNS issues

**Examples:**

``` bash
nslookup google.com
nslookup -type=MX google.com
nslookup 8.8.8.8
```
