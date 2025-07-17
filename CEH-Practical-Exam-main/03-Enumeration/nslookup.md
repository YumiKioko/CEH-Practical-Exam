## Basic Usage

```
nslookup target.com
```

Specify a DNS Server

```
nslookup target.com 8.8.8.8
```
Reverse DNS Lookup

```
nslookup 192.168.1.1
```
## Query Specific Record Types

### MX (Mail Exchange) Records

```
nslookup -query=MX target.com
```


NS (Name Server) Records

```
nslookup -query=NS target.com
```

TXT (Text) Records

```
nslookup -query=TXT target.com
```

Interactive Mode

```
nslookup
> server 8.8.8.8
> set type=MX
> target.com
```






