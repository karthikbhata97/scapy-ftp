# FTP client using Scapy

Usage:
```
sudo python2.7 client.py [-h] [-6] -u USER -l PASSWD -i IPADDR -p PORT
```

eg: sudo python2.7 client.py -u test -l test -i 172.16.1.125 -p 21

* Initially,  the client will do a TCP handshake with server on given PORT.
* The username and password is shared to log in to this session
* Commands can then be executed in the interactive terminal

* Help
```
python2.7 client.py -h
```

## Implementation

* Class FTPClient
	Takes input from user and sends it to the specified server.
* Class FTPListener
	For a given connection, it sniffs packets and acknowledges them accordingly as well as stores data recieved in them.
* Class FTPPassive
	When command brings up passive mode, it's object is used to communicate with server.



# FTP server using Scapy
	Under progress

Usage:
```
sudo python2.7 server.py [-h] [-p PORT] 
```

eg: sudo python2.7 server.py -p 31337

* Server will be listening on given port.
* Login credentials would be taken.
* Commands can then be executed supplied from the client.


* Help
```
python2.7 server.py -h
```

## Implementation

* Class FTPServer
	Creates new connection for each client
* Class FTPServerConnectiton
	Runs commands supplied by the client
* Class FTPListener
	For a given connection, it sniffs packets and acknowledges them accordingly as well as passes commands to the server connection.

