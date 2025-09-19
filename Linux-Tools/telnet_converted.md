Description: Telnet is a network protocol used to provide a
bidirectional interactive text-oriented communication facility using a
virtual terminal connection.

Basic Syntax:

bash telnet \[options\] \[host \[port\]\] Note: Telnet transmits data in
cleartext and is insecure. Prefer SSH for secure connections.

Common Use Cases:

Testing service connectivity

Manual interaction with services (SMTP, HTTP, etc.)

Network debugging

Examples:

bash telnet google.com 80 \# Test HTTP connection telnet mail.server.com
25 \# Test SMTP connection telnet 192.168.1.1 23 \# Connect to device's
telnet server

# Common service ports to test:

# 21 - FTP, 22 - SSH, 25 - SMTP, 80 - HTTP, 110 - POP3, 143 - IMAP, 443 - HTTPS

Interactive Commands (once connected):

Ctrl+\] then quit - Exit telnet session

Basic text input - Send commands to the service
