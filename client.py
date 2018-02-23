#! /usr/bin/python2.7

'''
usage: sudo python2.7 client.py [ftp-server-ip]

username and password is currently hardcoded
'''

from scapy.all import *
from random import randint
import sys



class FTPClinet:

	def __init__(self, dst):
		self.sport = random.randint(1024, 65535)
		# self.src = src
		self.dst = dst
		self.next_seq = 1000
		self.next_ack = 0
		self.basic_pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=21)
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

	def send_syn(self):
		synack = None
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=21, flags='S', seq=self.next_seq, ack=self.next_ack)
		while not synack:
			synack = sr1(ip/syn, timeout=1)

		self.next_seq = synack[TCP].ack
		return synack

	def send_ack(self, pkt):
		l = 0
		ip = IP(dst=self.dst)
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=21, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(ip/ack)

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def handshake(self):
		synack = self.send_syn()
		self.send_ack(synack)
		print "sniff called"
		sniff(timeout=4, lfilter=self.sniff_filter, prn=self.manage_resp)
		print "Handshake complete"

	def get_file(self, user, passwd, file):
		user = "USER " + user + '\r\n'
		passwd = "PASS " + passwd + '\r\n'
		file = "RETR " + file + '\r\n'
		pkt = self.basic_pkt
		pkt[TCP].flags = 'AP'
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		ftp_user = pkt/user
		self.send_pkt(ftp_user)
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		ftp_pass = pkt/passwd
		self.send_pkt(ftp_pass)
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		ftp_file = pkt/file
		# self.send_pkt(ftp_file)
	
	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src==self.dst and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == 21

	def manage_resp(self, pkt):
		print pkt.show()
		if (pkt[TCP].flags == 16L):
			self.next_seq = pkt[TCP].ack
		elif (pkt[TCP].flags & self.tcp_flags['TCP_ACK']):
			self.next_seq = pkt[TCP].ack
			self.send_ack(pkt)
		elif Raw in pkt:
			print pkt[Raw]
			send_ack(pkt)
		else:
			print 'Unknown'
			print pkt.show()
			send_ack(pkt)

	def send_pkt(self, pkt=None):
		if pkt:
			send(pkt)
		sniff(timeout=4, lfilter=self.sniff_filter, prn=self.manage_resp)
		return

	def close(self):
		resp = None
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		print pkt.show()
		while not resp:
			resp = sr1(pkt, timeout=4)
		# self.send_ack(resp)
		self.send_pkt(resp)

h = FTPClinet(sys.argv[1])
h.handshake()
h.get_file("anonymous", "", "testfile")
h.close()

