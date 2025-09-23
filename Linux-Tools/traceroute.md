
Description:
Traceroute tracks the pathway taken by a packet from source to destination and reports the IP addresses of all the routers it passes through.

Basic Syntax:

bash
traceroute [options] destination
Note: On some systems (particularly Windows), the command is tracert

Common Options:

-I - Use ICMP ECHO instead of UDP datagrams

-T - Use TCP SYN (default port 80)

-p port - Use specific port (with -T)

-n - Do not resolve IP addresses to hostnames

-w wait_time - Set timeout in seconds

-m max_ttl - Set maximum number of hops

-q nqueries - Set number of probes per hop

Common Use Cases:

Identify network routing path

Locate network bottlenecks

Diagnose connectivity issues

Identify points of failure

Examples:

bash
traceroute google.com                    # Basic traceroute
traceroute -I google.com                 # Use ICMP instead of UDP
traceroute -T google.com                 # Use TCP SYN packets
traceroute -p 443 google.com             # Use specific port
traceroute -n google.com                 # Don't resolve hostnames
traceroute -m 20 google.com              # Set max hops to 20
traceroute -w 2 google.com               # Set timeout to 2 seconds