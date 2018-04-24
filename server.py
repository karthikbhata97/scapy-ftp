from scapy.all import *
from random import randint
from threading import Thread
from time import sleep
import sys
import commands
from os import path

class FTPServerConnectiton:

	__dirname = path.abspath(".")
	__currdir = __dirname
	__pasv = False

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

	def __init__(self, src, dst, sport, dport, seqno, ackno):
		self.src = src
		self.dst = dst
		self.sport = sport
		self.dport = dport
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

	def send_ack(self, pkt):
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(basic_pkt/ack, verbose=self.verbose)

	def manage_resp(self, pkt):
		if not pkt[TCP].flags == self.tcp_flags['TCP_ACK']:
			self.send_ack(pkt)
		# manage ack


	def sniff_filter(self, pkt):
		if pkt.haslayer(IP) and pkt[IP].src == self.dst and pkt[IP].dst == self.src \
			and pkt.haslayer(TCP) and pkt[TCP].sport == self.dport and pkt[TCP].dport == self.sport:
			return True
		return False

	def finish(self, pkt):
		if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
			self.next_seq = pkt[TCP].ack
			self.send_ack(pkt)
			# need FIN?
			return True
		return False

	def run(self):
		sniff(prn=self.manage_resp, lfilter=self.sniff_filter, stop_filter=self.finish)

class FTPServer:
	def __init__(self, sport):
		self.sport = sport
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

	def handshake(self, pkt):
		dst = pkt[IP].src
		src = pkt[IP].dst
		dport = pkt[TCP].dport
		ackno = pkt[TCP].seq + 1
		seqno = 1000 # use random
		synack = IP(src=src, dst=dst)/TCP(sport=self.sport, dport=dport, flags='SA', seq=seqno, ack=ackno)
		reply = None
		while not reply:
			reply = sr1(synack, timeout=1)
		seqno += 1
		serv = FTPServerConnectiton(src, dst, self.sport, dport, seqno, ackno)
		serv_thread = Thread(target=serv.run)
		serv_thread.start()

	def sniff_filter(self, pkt):
		return pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].flags == self.tcp_flags['TCP_SYN'] 
		# and pkt.haslayer(IP) and pkt[IP].dst == self.src

	def run(self):
		sniff(prn=self.handshake, lfilter=self.sniff_filter)

