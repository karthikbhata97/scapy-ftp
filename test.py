from scapy.all import *

sport = random.randint(1024,65535)

# SYN
ip=IP(src='127.0.0.1',dst='127.0.0.1')
SYN=TCP(sport=sport,dport=21,flags='S',seq=1000)
SYNACK=sr1(ip/SYN)

# SYN-ACK
ACK=TCP(sport=sport, dport=21, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
send(ip/ACK)

