from scapy.all import *
from Queue import Queue

class FTPListener:
    # Initializes the fields
    def __init__(self, src, dst, sport, dport, seqno, ackno):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.data_share = Queue([100])
        self.next_seq = seqno
        self.next_ack = ackno
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
        self.basic_pkt = IP(src=self.src, dst=self.dst)/TCP(sport=self.sport, dport=self.dport)
        self.verbose = False

    # gets next ack number based on TCP segment length
    def get_next_ack(self, pkt):
        total_len = pkt.getlayer(IP).len
        ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
        tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
        ans = total_len - ip_hdr_len - tcp_hdr_len
        return (ans if ans else 1)

    # Sends ack packet
    def send_ack(self, pkt):
        self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
        pkt = self.basic_pkt
        pkt[TCP].flags = 'A'
        pkt[TCP].seq = self.next_seq
        pkt[TCP].ack = self.next_ack
        send(pkt, verbose=self.verbose)

    # filters packet based on port and ip. To get packet directed to current connection
    def sniff_filter(self, pkt):
        if pkt.haslayer(IP) and pkt[IP].src == self.dst and pkt[IP].dst == self.src \
            and pkt.haslayer(TCP) and pkt[TCP].sport == self.dport and pkt[TCP].dport == self.sport:
            return True
        return False

    # stopping condition for sniffing
    def finish(self, pkt):
        if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
            # self.next_seq = pkt[TCP].ack
            # self.send_ack(pkt)
            return True
        return False

    # manages recieved packet and replies accordingly
    def manage_resp(self, pkt):
        if Raw in pkt:
            self.data_share.put(pkt[Raw].load)

        self.next_seq = pkt[TCP].ack

        if (pkt[TCP].flags == self.tcp_flags['TCP_ACK']):
            pass
        else:
            self.send_ack(pkt)

        # manage ack

    # Starts listening on the wire
    def listen(self):
        sniff(prn=self.manage_resp, lfilter=self.sniff_filter, stop_filter=self.finish)

