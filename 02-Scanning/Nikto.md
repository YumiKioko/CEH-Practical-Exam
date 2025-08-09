## Example Usage

```
nikto -h http://target.com
```

### Common Options

- `-h`: Target host or URL
- `-p`: Specify port (default is 80)
- `-ssl`: Force SSL scan
- `-Tuning x`: Scan tuning options (e.g., file uploads, interesting files, etc.)
- `-output result.txt`: Save output to a file
## Example with SSL and output file

```
nikto -h https://target.com -output nikto_results.txt
```