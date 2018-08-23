from scapy.all import *
from queue import Queue
from threading import Thread, Lock
from time import sleep


class TCP_IPv6_Listener:

    def __init__(self, src, dst, sport, dport, seq_no, ack_no, verbose=False):

        self.src = src
        self.dst = dst
        
        self.sport = sport
        self.dport = dport

        self.next_seq = seq_no
        self.next_ack = ack_no

        self.verbose = verbose

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

        self.data_share = Queue(5000)
        self.dst_closed = False
        self.src_closed = False

        self.basic_pkt = IPv6(src=self.src, dst=self.dst)/\
                         TCP(sport=self.sport, dport=self.dport)

        self.ack_lock = Lock()
        self.ack_value = None
        self.ack_thread = Thread(target=self.send_ack_pkt)
        self.ack_thread.start()
        

    def sniff_filter(self, pkt):
        return pkt.haslayer(IPv6) and \
               (not self.src or self.src == pkt[IPv6].dst) and \
               (not self.dst or self.dst == pkt[IPv6].src) and \
               pkt.haslayer(TCP) and \
               (not self.sport or self.sport == pkt[TCP].dport) and \
               (not self.dport or self.dport == pkt[TCP].sport)


    def stop_filter(self, pkt):
        return self.src_closed and self.dst_closed


    def manage_pkt(self, pkt):

        if pkt.haslayer(Raw):
            # print (pkt[TCP].seq, self.next_ack)
            if pkt[TCP].seq >= self.next_ack:
                self.data_share.put(pkt[Raw].load)

        if pkt[TCP].flags == self.tcp_flags['TCP_SYN']:
            self.next_ack = pkt[TCP].seq + 1

            pkt = self.basic_pkt
            pkt[TCP].flags = 'SA'
            pkt[TCP].seq = self.next_seq
            pkt[TCP].ack = self.next_ack

            send(pkt)
            return

        self.next_seq = pkt[TCP].ack

        if pkt[TCP].flags == self.tcp_flags['TCP_ACK']:
            pass
        else:
            self.send_ack(pkt)

        if pkt[TCP].flags & self.tcp_flags['TCP_FIN']:
            while self.ack_value:
                pass
            self.dst_closed = True


    def get_next_ack(self, pkt):
        total_len = pkt.getlayer(IPv6).plen
        tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
        ans = int(total_len - tcp_hdr_len)
        return (ans if ans else 1)


    def send_ack_pkt(self):
        pkt = self.basic_pkt
        pkt[TCP].flags = 'A'
        while not (self.src_closed and self.dst_closed):
            with self.ack_lock:
                if not self.ack_value:
                    pass
                else:
                    pkt[TCP].seq = self.ack_value[0]
                    pkt[TCP].ack = self.ack_value[1]
                    send(pkt, verbose=self.verbose) 
                    self.ack_value = None
            sleep(0.1)
                    

    def send_ack(self, pkt):
        self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
        with self.ack_lock:
            self.ack_value = (self.next_seq, self.next_ack)


    def listen(self):
        sniff(lfilter=self.sniff_filter, prn=self.manage_pkt, stop_filter=self.stop_filter)

