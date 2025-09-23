
Description:
Whois is a protocol used to query databases that store registered users or assignees of domain names, IP addresses, and autonomous system numbers.

Basic Syntax:

bash
whois [options] domain_name
Common Commands:

whois example.com - Basic domain lookup

whois 192.168.1.1 - IP address lookup

whois -h whois.server.com example.com - Query specific whois server

Useful Options:

-H - Hide legal disclaimers

-p port - Connect to specific port

-a - Find all matching records

Common Use Cases:

Check domain availability

Identify domain owner/registrar

View domain creation/expiration dates

Find contact information (though often redacted now)

Examples:

bash
whois google.com
whois 8.8.8.8
whois -H example.com  # Hide legal disclaimers
