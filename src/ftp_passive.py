from scapy.all import *
from threading import Thread
from ftp_listener import FTPListener
from time import sleep
import random


class FTPPassive:
    """
    Used as a thread for a passive connections. Works similar to client class.
    Except it has file send and recieve functions
    """

    def __init__(self, dst, dport, interact=True, logfile=None):
        """
        Initializes all the fields.
        dst (str): destination ip address
        dport (int): destination port
        interact (bool): uses print to output to console # TODO use logger
        logfile (str): Incase of logging output into a file
        """
        self.sport = random.randint(1024, 65535)
        self.dport = dport

        self.src = None
        self.dst = dst

        self.basic_pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=self.dport)
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
        self.interact = interact
        self.logfile = logfile

        self.listener = FTPListener(self.sport, self.dport, self.dst, interact=self.interact, logfile=self.logfile)
        self.listen_thread = Thread(target = self.listener.listen)
        self.listen_thread.start()


    def send_syn(self):
        """
        Sends syn packet. Waits for ack
        """
        ip = IP(dst=self.dst)
        syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
        pkt = ip/syn
        seq_next = self.listener.next_seq 
        while self.listener.next_seq == seq_next:
            send(pkt, verbose=self.verbose)
            sleep(1)
        return


    def handshake(self):
        """
        Initializes handshake with the help of send_syn
        """
        self.send_syn()


    def get_next_ack(self, pkt):
        """
        Returns the length of TCP body to determine next ack number.
        """
        total_len = pkt.getlayer(IP).len
        ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
        tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
        ans = total_len - ip_hdr_len - tcp_hdr_len
        return (ans if ans else 1)


    def close(self):
        """
        Closes TCP connection.
        """
        pkt = self.basic_pkt
        pkt[TCP].flags = 'FA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        send(pkt, verbose=self.verbose)
        self.listen_thread.join()


    def send_pkt(self, pkt):
        """
        Sends a packet and waits for acknowledgement.
        """
        seq_next = self.listener.next_seq 
        while self.listener.next_seq == seq_next:
            send(pkt, verbose=self.verbose)
            sleep(1)
        return


    def recvfile(self, file):
        """
        Copies data from the listener thread's shared queue into the file.
        """
        with open(file, "w") as f:
            while True:
                if not self.listener.data_share.empty():
                    f.write(self.listener.data_share.get())
                if self.listener.data_share.empty() and not self.listen_thread.isAlive():
                    break


    def sendfile(self, file):
        """
        Sends the content of the file in chunks of 512 bytes.
        """
        with open(file, "r") as f:
            data = f.read()
            chunks = [data[i:i+512] for i in range(0, len(data), 512)]
        for item in chunks:
            pkt = self.basic_pkt
            pkt[TCP].flags = 'AP'
            pkt[TCP].seq = self.listener.next_seq
            pkt[TCP].ack = self.listener.next_ack
            pkt = pkt/Raw(load=item)
            self.send_pkt(pkt)
        
        # self.close()


