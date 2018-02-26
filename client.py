#! /usr/bin/python2.7

'''
usage: sudo python2.7 client.py [ftp-server-ip]

username and password is currently hardcoded
'''

from scapy.all import *
from random import randint
from threading import Thread
from time import sleep
import sys

class FTPPassive:
	def __init__(self, dst, dport):
		self.sport = random.randint(1024, 65535)
		self.dport = dport
		self.src = None
		self.dst = dst
		self.next_seq = 1000
		self.next_ack = 0
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


	def send_syn(self):
		synack = None
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.next_seq, ack=self.next_ack)
		while not synack:
			synack = sr1(ip/syn, timeout=1)

		self.next_seq = synack[TCP].ack
		return synack

	def send_ack(self, pkt):
		l = 0
		ip = IP(dst=self.dst)
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(ip/ack)

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def handshake(self):
		synack = self.send_syn()
		self.src = synack[IP].src
		self.send_ack(synack)
		print "sniff called"
		sniff(timeout=4, lfilter=self.sniff_filter, prn=self.manage_resp)
		print "Handshake complete"

	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src==self.dst and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dport

	def manage_resp(self, pkt):
		print pkt.show()
		self.next_seq = pkt[TCP].ack
		if (pkt[TCP].flags == 16L):
			pass
		elif (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
			self.send_ack(pkt)
		elif (pkt[TCP].flags & self.tcp_flags['TCP_ACK']):
			self.send_ack(pkt)
		elif Raw in pkt:
			print pkt[Raw]
			send_ack(pkt)
		else:
			print 'Unknown'
			print pkt.show()
			send_ack(pkt)

	def run(self):
		self.handshake()
		sniff(lfilter=self.sniff_filter, prn=self.manage_resp, stop_filter=self.finish)
		return

	def finish(self, pkt):
		if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
			self.next_seq = pkt[TCP].ack
			self.send_ack(pkt)
			return True
		return False
		
	def send_pkt(self, pkt=None):
		if pkt:
			send(pkt)
		sniff(timeout=4, lfilter=self.sniff_filter, prn=self.manage_resp)
		self.close()
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



class FTPClinet:
	def __init__(self, dst):
		self.sport = random.randint(1024, 65535)
		self.dport = 21
		self.src = None
		self.dst = dst
		self.next_seq = 1000
		self.next_ack = 0
		self.basic_pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=self.dport)
		self.data_pkt = IP(dst=self.dst)/TCP(sport=self.sport, dport=self.dport)
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

		self.passive_port = None

	def send_syn(self):
		synack = None
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.next_seq, ack=self.next_ack)
		while not synack:
			synack = sr1(ip/syn, timeout=1)

		self.next_seq = synack[TCP].ack
		return synack

	def send_ack(self, pkt):
		l = 0
		ip = IP(dst=self.dst)
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(ip/ack)

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def handshake(self):
		synack = self.send_syn()
		self.src = synack[IP].src
		self.send_ack(synack)
		print "sniff called"
		sniff(timeout=4, lfilter=self.sniff_filter, prn=self.manage_resp)
		print "Handshake complete"


	def login(self, user, passwd):
		user = "USER " + user + '\r\n'
		passwd = "PASS " + passwd + '\r\n'
		# file = "RETR " + file + '\r\n'
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
		# pkt[TCP].seq = self.next_seq
		# pkt[TCP].ack = self.next_ack
		# ftp_file = pkt/file
		# self.send_pkt(ftp_file)
	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src==self.dst and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dport

	def manage_resp(self, pkt):
		print pkt.show()
		self.next_seq = pkt[TCP].ack
		if (pkt[TCP].flags == self.tcp_flags['TCP_ACK']):
			pass
		elif Raw in pkt and pkt[Raw].load[0:3] == '227':
			ip_port = pkt[Raw].load.split('(')[1].split(')')[0].split(',')
			port = int(ip_port[-2]) * 256 + int(ip_port[-1])
			self.passive_port = port
			self.send_ack(pkt)
		elif (pkt[TCP].flags & self.tcp_flags['TCP_ACK']):
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

	def interactive(self):
		command = ""
		while True:
			sys.stdout.write("\n>> ")
			command = raw_input() + '\r\n'
			if command == 'exit\r\n':
				break
			self.passive()
			pkt = self.basic_pkt
			pkt[TCP].flags = 'AP'
			pkt[TCP].seq = self.next_seq
			pkt[TCP].ack = self.next_ack
			cmd = pkt/command
			passive_thread = Thread(target = self.manage_passive)
			passive_thread.start()
			sleep(4)
			self.send_pkt(cmd)
			passive_thread.join()
			self.send_pkt()

		self.close()

	def passive(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'AP'
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		cmd = "PASV\r\n"
		pasv = pkt/cmd
		self.send_pkt(pasv)
		print self.passive_port

	def manage_passive(self):
		print "Check Check: %d" % self.passive_port
		passive = FTPPassive(self.dst, self.passive_port)
		passive.run()
		print "\n" * 10
		print "Success\t" * 100
		print "\n" * 5
		return


h = FTPClinet(sys.argv[1])
h.handshake()
h.login("anonymous", "")
h.interactive()

