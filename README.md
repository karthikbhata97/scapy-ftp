# FTP client using Scapy

Usage:
```
sudo python2.7 client.py [server's ip] [ftp user] [ftp password]
```

eg: sudo python2.7 client.py 192.168.43.155 test test

* Initially,  the client will do a TCP handshake with server on port 21.
* The username and password is shared to log in to this session
* Commands can then be executed in the interactive terminal