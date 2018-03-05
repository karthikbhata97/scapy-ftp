
from scapy.all import *
from random import randint
from threading import Thread
from time import sleep
import sys

cmd_passive = ['LIST', 'RETR']

class FTPListener:
	def __init__(self, sport, dport, dst):
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

	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src==self.dst and (not self.src or pkt[IP].dst == self.src) and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dport

	def manage_resp(self, pkt):
		if Raw in pkt:
			print pkt[Raw].load

		if Raw in pkt and pkt[Raw].load[0:3] == '227':
			ip_port = pkt[Raw].load.split('(')[1].split(')')[0].split(',')
			port = int(ip_port[-2]) * 256 + int(ip_port[-1])
			self.passive_port = port

		self.next_seq = pkt[TCP].ack
		next_ack = self.get_next_ack(pkt)

		if (pkt[TCP].flags == self.tcp_flags['TCP_ACK']):
			if next_ack != 1:
				self.send_ack(pkt)
		else:
			self.send_ack(pkt)

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def listen(self):
		sniff(lfilter=self.sniff_filter, prn=self.manage_resp, stop_filter=self.finish)

	def send_ack(self, pkt):
		ip = IP(dst=self.dst)
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(ip/ack, verbose=self.verbose)

	def finish(self, pkt):
		if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
			self.next_seq = pkt[TCP].ack
			self.send_ack(pkt)
			return True
		return False

	def get_passive_port(self):
		return self.passive_port


class FTPPassive:
	def __init__(self, dst, dport):
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
		self.listener = FTPListener(self.sport, self.dport, self.dst)
		self.listen_thread = Thread(target = self.listener.listen)
		self.listen_thread.start()

	def send_syn(self):
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
		pkt = ip/syn
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	def handshake(self):
		self.send_syn()

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def close(self):
		self.listen_thread.join()
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		sr1(pkt, verbose=self.verbose)


class FTPClient:
	def __init__(self, dst):
		self.sport = random.randint(1024, 65535)
		self.dport = 21
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
		self.passive_port = None
		self.verbose = False
		self.listener = FTPListener(self.sport, self.dport, self.dst)
		self.listen_thread = Thread(target = self.listener.listen)
		self.listen_thread.start()
		self.passive_obj = None

	def send_syn(self):
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
		pkt = ip/syn
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	def send_pkt(self, pkt):
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	def handshake(self):
		self.send_syn()

	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	def passive(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'AP'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		cmd = "PASV\r\n"
		pasv = pkt/cmd
		self.send_pkt(pasv)
		self.passive_port = self.listener.get_passive_port()

	def manage_passive(self):
		passive = FTPPassive(self.dst, self.passive_port)
		passive.handshake()
		return passive

	def close(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		sr1(pkt, verbose=self.verbose)
		self.listen_thread.join()

	def interactive(self):
		command = ""
		while True:
			sys.stdout.write("\n>> ")
			command = raw_input() + '\r\n'
			if command == 'exit\r\n':
				self.close()
				return
			base_cmd = command.split('\r')[0].split(' ')[0]
			if base_cmd in cmd_passive:
				self.passive()
				self.passive_obj = self.manage_passive() 
				pkt = self.basic_pkt
				pkt[TCP].flags = 'AP'
				pkt[TCP].seq = self.listener.next_seq
				pkt[TCP].ack = self.listener.next_ack
				cmd = pkt/command
				self.send_pkt(cmd)
				self.passive_obj.close()
			else:
				pkt = self.basic_pkt
				pkt[TCP].flags = 'AP'
				pkt[TCP].seq = self.listener.next_seq
				pkt[TCP].ack = self.listener.next_ack
				cmd = pkt/command
				self.send_pkt(cmd)


client = FTPClient(sys.argv[1])
client.handshake()
client.interactive()