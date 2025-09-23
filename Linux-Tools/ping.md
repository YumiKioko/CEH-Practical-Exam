# Ping

**Description:**\
`ping` tests connectivity between two hosts by sending ICMP echo
requests and measuring response times.

**Basic Syntax:**

``` bash
ping [options] destination
```

**Common Options:** - `-c count` -- Number of packets to send\
- `-i interval` -- Interval between packets (seconds)\
- `-s size` -- Packet size in bytes\
- `-t ttl` -- Set TTL (Time to Live) value\
- `-W timeout` -- Timeout per reply (seconds)

**Use Cases:** - Check host availability\
- Measure latency\
- Detect packet loss

**Examples:**

``` bash
ping google.com
ping -c 5 google.com         # Send 5 packets
ping -s 128 google.com       # Send 128-byte packets
ping -W 2 google.com         # Timeout after 2 seconds
```
