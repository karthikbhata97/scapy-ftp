from scapy.all import *
from Queue import Queue

class FTPListener:
    """
    Listener class used for listening the responses in a TCP session. It should be run on a thread, which
    will be continuously listening and acknowledging the packets.
    """
    def __init__(self, sport, dport, dst, interact=True, logfile=None):
        """
        Initializes the source and destination options for the TCP connection to be listened.
        """
        self.sport = sport
        self.dport = dport

        self.src = None
        self.dst = dst
        
        self.next_seq = 1000
        self.next_ack = 1
        
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

        self.verbose = False
        self.passive_port = None

        self.data_share = Queue([50000])

        self.interact = interact 
        self.logfile = logfile


    def sniff_filter(self, pkt):
        """
        Filter for the packets to be sniffed based on TCP source and destination options.
        """
        return pkt.haslayer(IP) and pkt[IP].src==self.dst and (not self.src or pkt[IP].dst == self.src) and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dport


    def manage_resp(self, pkt):
        """
        Callback function from sniff, it takes each packet and gives acknowledgement as well as saves data.
        """
        if Raw in pkt:
            if self.interact:
                print pkt[Raw].load
            else:
                with open(self.logfile, 'a') as f:
                    f.write(pkt[Raw].load)
                    
            self.data_share.put(pkt[Raw].load)

        if Raw in pkt and pkt[Raw].load[0:3] == '227':
            ip_port = pkt[Raw].load.split('(')[1].split(')')[0].split(',')
            port = int(ip_port[-2]) * 256 + int(ip_port[-1])
            self.passive_port = port

        self.next_seq = pkt[TCP].ack
        next_ack = self.get_next_ack(pkt)

        if (pkt[TCP].flags == self.tcp_flags['TCP_ACK']):
            # if next_ack != 1:
                # self.send_ack(pkt)
            pass
        else:
            self.send_ack(pkt)


    def get_next_ack(self, pkt):
        """
        Helper function to fetch next acknowlegement number.
        """
        total_len = pkt.getlayer(IP).len
        ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
        tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
        ans = total_len - ip_hdr_len - tcp_hdr_len
        return (ans if ans else 1)


    def listen(self):
        """
        Helper function to call scapy sniff
        """
        sniff(lfilter=self.sniff_filter, prn=self.manage_resp, stop_filter=self.finish)


    def send_ack(self, pkt):
        """
        Helper function to send acknowledgement.
        """
        ip = IP(dst=self.dst)
        self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
        ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
        send(ip/ack, verbose=self.verbose)


    def finish(self, pkt):
        """
        Condition for end of TCP connection
        """
        if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
            # self.next_seq = pkt[TCP].ack
            # self.send_ack(pkt)
            return True
        return False


    def get_passive_port(self):
        """
        Getter for passive_port
        """
        return self.passive_port
