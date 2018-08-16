# FTP client using Scapy

### Requirements
* Scapy on Python2.7
* Update iptables to prevent sending RST
  ```
  bash update_iptables.sh
  ``` 


Usage:
```
sudo python2.7 client/client.py [-h] -u USER -l PASSWD -i IPADDR -p PORT [-m MULTIPLE] [-c COMMAND_FILE]

optional arguments:
  -h, --help            show this help message and exit

  -u USER, --user USER  
  Username for FTP login

  -l PASSWD, --passwd PASSWD
  Password for FTP login

  -i IPADDR, --ipaddr IPADDR
  FTP server IP address

  -p PORT, --port PORT
  FTP server port number

  -m MULTIPLE, --multiple MULTIPLE
  Open multiple connections to FTP server

  -c COMMAND_FILE, --command_file COMMAND_FILE
  Run commands from given file for multiple connections.
  Each line has n(number of multiple connections) comma seperated FTP commands.
```

eg: sudo python2.7 client/client.py -u test -l test -i 172.16.1.125 -p 21

* Initially,  the client will do a TCP handshake with server on given PORT.
* The username and password is shared to log in to this session
* Commands can then be executed in the interactive terminal

* Help
```
python2.7 client/client.py -h
```

## Implementation

#### Class FTPClient (ftp_client.py)
- Takes input from user and sends it to the specified server.

#### Class FTPListener (ftp_listener.py)
- For a given connection, it sniffs packets and acknowledges them accordingly as well as stores data recieved in them.

#### Class FTPPassive (ftp_passive.py)
- When command brings up passive mode, it's object is used to communicate with server.



# FTP server using Scapy
    Under progress

Usage:
```
sudo python2.7 server/server.py [-h] [-p PORT] 
```

eg: sudo python2.7 server/server.py -p 31337

* Server will be listening on given port.
* Login credentials would be taken.
* Commands can then be executed supplied from the client.


* Help
```
python2.7 server/server.py -h
```

## Implementation

#### Class FTPServer (ftp_server.py)
- Creates new connection for each client
#### Class FTPServerConnectiton (ftp_server_conn.py)
- Runs commands supplied by the client
#### Class FTPListener (ftp_listener.py)
- For a given connection, it sniffs packets and acknowledges them accordingly as well as passes commands to the server connection.
#### Class FTPPassiveServer (ftp_passive_server.py)
- For passive mode commands.
