import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from random import randint
from threading import Thread
from time import sleep
import sys
import commands
from os import path
from Queue import Queue
import argparse


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
        ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
        send(self.basic_pkt/ack, verbose=self.verbose)

    # filters packet based on port and ip. To get packet directed to current connection
    def sniff_filter(self, pkt):
        if pkt.haslayer(IP) and pkt[IP].src == self.dst and pkt[IP].dst == self.src \
            and pkt.haslayer(TCP) and pkt[TCP].sport == self.dport and pkt[TCP].dport == self.sport:
            return True
        return False

    # stopping condition for sniffing
    def finish(self, pkt):
        if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
            self.next_seq = pkt[TCP].ack
            self.send_ack(pkt)
            # need FIN?
            return True
        return False

    # manages recieved packet and replies accordingly
    def manage_resp(self, pkt):
        if pkt[TCP].flags & self.tcp_flags['TCP_ACK']:
            self.next_seq = pkt[TCP].ack
        if not pkt[TCP].flags == self.tcp_flags['TCP_ACK']:
            self.send_ack(pkt)
        if pkt[TCP].flags & self.tcp_flags['TCP_FIN']:
            fin = self.basic_pkt
            fin[TCP].flags = 'F'
            send(fin, verbose=self.verbose)

        if Raw in pkt:
            self.data_share.put(pkt[Raw].load)
        # manage ack

    # Starts listening on the wire
    def run(self):
        sniff(prn=self.manage_resp, lfilter=self.sniff_filter, stop_filter=self.finish)

class FTPServerConnectiton:

    __dirname = path.abspath(".")
    __currdir = __dirname
    __pasv = False
    __finish = False

    # FTP responses
    __resp = {
        'welcome': '220 Welcome!\r\n',
        'cmd_error': '500 Syntax error, command unrecognized.\r\n',
        'goodbye': '221 Goodbye.\r\n',
        'username_ok': '331 User name okay, need password.\r\n',
        'username_error': '530 Not logged in.Try anonymous or valid account\r\n',
        'password_ok': '230 Password OK.User logged in.\r\n',
        'password_error': '530 Incorrect password.Not logged in.\r\n',
        'syst_msg': '215 UNIX Type: L8\r\n',
        'type_set': '200 Type set to %s.\r\n',
        'curr_dir': '257 "%s" is the current directory.\r\n',
        'not_file': '550 %s: not a regular file.\r\n',
        'dir_changed': '250 Directory changed.\r\n',
        'dir_changed_root': '250 Directory changed to root.\r\n',
        'path_not_found': '550 Path not found.Directory not changed\r\n',
        'path_not_dir': '550 Path is not a directory.Directory not changed\r\n',
        'use_pasv': '425 Use PASV or PORT first.\r\n',
        'open_data_conn': '150 Opening data connection.\r\n',
        'transfer_complete': '226 Transfer complete.\r\n',
        'dir_list': '150 Here comes the directory listing.\r\n',
        'pasv_mode': '227 Entering Passive Mode (%s,%u,%u).\r\n',
    }

    # initialize the fields
    def __init__(self, src, dst, sport, dport, seqno, ackno):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
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
        self.listener = FTPListener(src, dst, sport, dport, seqno, ackno)
        self.listener_thread = Thread(target=self.listener.run)
        self.listener_thread.start()

    # Run the commands
    def command(self, cmd):
        print 'command %s recieved' % (cmd,)

        def default_resp(cmd):
            self.send_data('Not yet implemented or Invalid query\r\n')

        action = getattr(self, cmd.split(' ')[0], default_resp)
        action(cmd)

    # Functions for respective commands

    def USER(self, cmd):
        try:
            self.user = cmd.split(' ')[1]
        except:
            self.send_data(self.__resp['cmd_error'])
            return
        self.send_data(self.__resp['username_ok'])

    def PASS(self, cmd):
        try:
            self.passwd = cmd.split(' ')[1]
        except:
            self.send_data(self.__resp['cmd_error'])
            return
        self.send_data(self.__resp['password_ok'])


    def SYST(self, cmd):
        self.send_data(self.__resp['syst_msg'])

    # Put the reply into a packet
    def send_data(self, data):
        pkt = self.basic_pkt/Raw(load=data)
        self.send_pkt(pkt)

    # send the packet
    def send_pkt(self, pkt):
        pkt[TCP].flags = 'PA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        while self.listener.next_seq == pkt[TCP].seq:
            sr1(pkt, timeout=1, verbose=self.verbose)

    # server start
    def run(self):
        self.send_data(self.__resp['welcome'])
        while not self.__finish:
            if not self.listener.data_share.empty():
                cmd = self.listener.data_share.get().strip()
                self.command(cmd)



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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', help='Port on which server runs', nargs=1, type=int, default=21)
    args = parser.parse_args()
    port = args.port[0]
    server = FTPServer(port)
    server.run()