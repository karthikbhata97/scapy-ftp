# FTP client using Scapy

Usage:
```
sudo python2.7 client.py [-h] [-6] -u USER -l PASSWD -i IPADDR -p PORT
```

eg: sudo python2.7 client.py -u test -l test -i 172.16.1.125 -p 21

* Initially,  the client will do a TCP handshake with server on given PORT.
* The username and password is shared to log in to this session
* Commands can then be executed in the interactive terminal

## Implementation

* Class FTPClient
	Takes input from user and sends it to the specified server.
* Class FTPListener
	For a given connection, it sniffs packets and acknowledges them accordingly as well as stores data recieved in them.
* Class FTPPassive
	When command brings up passive mode, it's object is used to communicate with server.

