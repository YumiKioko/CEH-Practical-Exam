## Basic Directory Bruteforce

```
ffuf -u http://target.com/FUZZ -w /path/to/wordlist.txt
```

## Directory and File Discovery

```
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

## Virtual Host Discovery

```
ffuf -u http://FUZZ.target.com -w subdomains.txt -H "Host: FUZZ.target.com"
```

## File Extension Bruteforce

```
ffuf -u http://target.com/FUZZ.php -w wordlist.txt
```

## Filter by Status Code

```
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404
```

## Filter by Response Size

```
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 4242
```

## Output to File

```
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json
```