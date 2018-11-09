# FTP client and server using Scapy (IPv6 and IPv4, python3)

### Requirements
* Python3(3.6) with Scapy
* netifaces
* Update iptable rules
  ```
  bash update_iptables.sh
  ```

```
This makes use of TCP connection class designed for implementing a TCP connection using Scapy module.
Source: https://github.com/karthikbhata97/ScapyTCP
```

## Client

Usage:
```
sudo python3.6 ipv6/client.py client.py [-h] --iface IFACE -i HOST -p PORT
sudo python3.6 ipv4_python3/client.py client.py [-h] --iface IFACE -i HOST -p PORT
```

eg: sudo python3.6 client.py --iface wlp3s0 -i  fe80::a00:27ff:fe1e:e615 -p 21
eg: sudo python3.6 client.py --iface wlp3s0 -i 192.168.0.7 -p 21

* Help
```
python3.6 ipv6/client.py -h
python3.6 ipv4_python3/client.py -h
```

* Client will connect to server based on given interface.
* Session is logged in based on the credentials.
* Supplied commands will be sent to server and response is shown.

## Implementation

#### Class FTPClient
- Takes the commands as input and sends them over TCP/IPv6

#### Class TCP_IPv6
- Implements TCP/IPv6 stacks which can be made use by any of upper layer protocols.

#### Class TCP_IPv6_Connection
- Listener for the TCP_IPv6 class, reads packets and acknowledges them.


## Server

Usage:
```
sudo ipv6/server.py [-h] --iface IFACE -p PORT
sudo ipv4_python3/server.py [-h] --iface IFACE -p PORT
```

## Implementation

### Class FTPServer
- Main thread which assigns a new thread of Server connection for each new connection.

### Class FTP_Server_Conn
- Implements FTP control connection.

### Class FTP_Data_Conn
- Implements FTP data conneciton.


# FTP client using Scapy (IPv4, python2)

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



# FTP server using Scapy (IPv4, python2)

### Requirements
* Scapy on Python2.7
* Update iptables to prevent sending RST
  ```
  bash update_iptables.sh
  ``` 

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


