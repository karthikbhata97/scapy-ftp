from scapy.all import *
from ftp_listener import FTPListener
from threading import Thread
from subprocess import check_output
from os import path


class FTPPassiveServer:

    def __init__(self, src, dst, sport, dport, verbose=False):
        self.src = src
        self.dst = dst

        self.sport = sport
        self.dport = dport

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

        self.handshake_complete = False
        self.verbose = verbose
        self.__stor_complete = False

    def handshake(self, pkt):
        pkt.summary()
        self.dport = pkt[TCP].sport
        self.next_ack = pkt[TCP].seq + 1
        synack = IP(src=self.src, dst=self.dst)/TCP(sport=self.sport, dport=self.dport, flags='SA', seq=self.next_seq, ack=self.next_ack)
        reply = None
        while not reply:
            reply = sr1(synack, timeout=1, verbose=self.verbose)
        self.next_seq += 1
        self.handshake_complete = True

        self.basic_pkt = IP(src=self.src, dst=self.dst)/TCP(sport=self.sport, dport=self.dport)

        self.listener = FTPListener(self.src, self.dst, self.sport, self.dport, self.next_seq, self.next_ack)
        self.listener_thread = Thread(target=self.listener.listen)
        self.listener_thread.start()

    # Filter packets to be recieved based on port and flag (SYN)
    def sniff_filter(self, pkt):
        return pkt.haslayer(IP) and pkt[IP].dst == self.src and pkt[IP].src == self.dst and \
               pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and \
               pkt[TCP].flags == self.tcp_flags['TCP_SYN'] 
        # and pkt.haslayer(IP) and pkt[IP].dst == self.src


    def stop_filter(self, pkt):
        return self.handshake_complete


    def run(self):
        sniff(prn=self.handshake, lfilter=self.sniff_filter, stop_filter=self.stop_filter)


    # Put the reply into a packet
    def send_data(self, data):
        data = data.replace('\n', '\r\n')

        chunk_sz = 512
        data_chunks = [data[i:i+chunk_sz] for i in range(0, len(data), chunk_sz)]
        for data in data_chunks:
            pkt = self.basic_pkt/Raw(load=data)
            self.send_pkt(pkt)


    # send the packet
    def send_pkt(self, pkt):
        pkt[TCP].flags = 'PA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        while self.listener.next_seq == pkt[TCP].seq:
            sr1(pkt, timeout=1, verbose=self.verbose)


    def close(self):
        """
        Close TCP connection.
        """
        # In case handshake is not complete but still want to close
        self.handshake_complete = True

        pkt = self.basic_pkt
        pkt[TCP].flags = 'FA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        send(pkt, verbose=self.verbose)
        self.listener_thread.join()


    def LIST(self, cmd, currdir):
        dir_list = check_output(['ls', '-l', currdir])
        dir_list = dir_list.split('\n', 1)[1]

        self.send_data(dir_list)
        self.close()


    def RETR(self, cmd, filename):

        with open(filename, 'rb') as f:
            data = f.read()

        self.send_data(data)
        self.close()


    def STOR(self, cmd, filename):
        while not self.listener.__closed: 

            if not self.listener.data_share.empty():
                data = self.listener.data_share.get()
                with open(filename, 'a') as f:
                    f.write(data)

        self.close()