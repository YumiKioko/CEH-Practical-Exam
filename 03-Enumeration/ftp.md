
```
ftp <machine_ip>
```

Example commands defined by the FTP protocol are:

- `USER` is used to input the username
- `PASS` is used to enter the password
- `RETR` (retrieve) is used to download a file from the FTP server to the client.
- `STOR` (store) is used to upload a file from the client to the FTP server.

- We used the username `anonymous` to log in
- We didn't need to provide any password
- Issuing `ls` returned a list of files available for download

`type ascii` switched to ASCII mode as this is a text file (optional | I didn't had to do this)

`get coffee.txt` allowed us to retrieve the file we want (in this case coffee.txt)