from ftp_server_conn import FTPServerConnectiton
from scapy.all import *
from threading import Thread


class FTPServer:
    # initialize the fields
    def __init__(self, sport):
        self.sport = sport
        self.verbose = False
        self.tcp_flags = {
            'TCP_FIN': 0x01, 
            'TCP_SYN': 0x02, 
            'TCP_RST': 0x04, 
            'TCP_PSH': 0x08, 
            'TCP_ACK': 0x10, 
            'TCP_URG': 0x20, 
            'TCP_ECE': 0x40, 
            'TCP_CWR': 0x80
        }

    # complete the handshake with the client
    def handshake(self, pkt):
        pkt.summary()
        dst = pkt[IP].src
        src = pkt[IP].dst
        dport = pkt[TCP].sport
        ackno = pkt[TCP].seq + 1
        seqno = 0 # use random
        synack = IP(src=src, dst=dst)/TCP(sport=self.sport, dport=dport, flags='SA', seq=seqno, ack=ackno)
        reply = None
        while not reply:
            reply = sr1(synack, timeout=1, verbose=self.verbose)
        seqno += 1
        serv = FTPServerConnectiton(src, dst, self.sport, dport, seqno, ackno)
        serv_thread = Thread(target=serv.run)
        serv_thread.start()
        print 'New connection created'

    # Filter packets to be recieved based on port and flag (SYN)
    def sniff_filter(self, pkt):
        return pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].flags == self.tcp_flags['TCP_SYN'] 
        # and pkt.haslayer(IP) and pkt[IP].dst == self.src

    def run(self):
        sniff(prn=self.handshake, lfilter=self.sniff_filter)

