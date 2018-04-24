import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from random import randint
from threading import Thread
from time import sleep
import sys
from Queue import Queue
import argparse

cmd_passive = ['LIST', 'RETR', 'STOR']
cmd_sender = ['STOR']

class FTPListener:
	'''	
		Initializes fields
	'''
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
		self.data_share = Queue([50000]) 

	'''
		sniff_filter: filters packet based on port it is listening on
	'''
	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src==self.dst and (not self.src or pkt[IP].dst == self.src) and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport and pkt[TCP].sport == self.dport

	'''
		manage_resp: Based on recieved packet, constructs the reply
	'''
	def manage_resp(self, pkt):
		if Raw in pkt:
			print pkt[Raw].load
			self.data_share.put(pkt[Raw].load)

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


	'''
		get_next_ack: Update the next_ack based on segment length of recieved packet.
	'''
	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	'''
		listen: sniffs packets and filters based on helper functions
	'''
	def listen(self):
		sniff(lfilter=self.sniff_filter, prn=self.manage_resp, stop_filter=self.finish)

	'''
		send_ack: Acknowledges the recieved packet
	'''
	def send_ack(self, pkt):
		ip = IP(dst=self.dst)
		self.next_ack = pkt[TCP].seq + self.get_next_ack(pkt)
		ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.next_seq, ack=self.next_ack)
		send(ip/ack, verbose=self.verbose)

	'''
		finish: end of sniffing condition
	'''
	def finish(self, pkt):
		if pkt.haslayer(TCP) and (pkt[TCP].flags & self.tcp_flags['TCP_FIN']):
			self.next_seq = pkt[TCP].ack
			self.send_ack(pkt)
			return True
		return False

	'''
		get_passive_port: Returns passive port it is listening on
	'''
	def get_passive_port(self):
		return self.passive_port


class FTPPassive:
	'''	
		Initializes fields
	'''
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

	'''
		send_syn: sends SYN packet.
	'''
	def send_syn(self):
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
		pkt = ip/syn
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	'''
		handshake: Initialize handshake
	'''
	def handshake(self):
		self.send_syn()

	'''
		get_next_ack: Update the next_ack based on segment length of recieved packet.
	'''
	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)


	'''
		close: closes the TCP connection. Issue found. To be fixed 
	'''
	def close(self):
		self.listen_thread.join()
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		sr1(pkt, verbose=self.verbose)

	'''
		send_pkt: Puts packet on the wire
	'''
	def send_pkt(self, pkt):
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	'''
		recvfile: saves the file recieved (RETR)
	'''
	def recvfile(self, file):
		with open(file, "w") as f:
			while True:
				if not self.listener.data_share.empty():
					f.write(self.listener.data_share.get())
				if self.listener.data_share.empty() and not self.listen_thread.isAlive():
					break

	'''
		sendfile: Reads file to be sent (STOR) and sends it to server
	'''
	def sendfile(self, file):
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


class FTPClient:
	'''	
		Initializes fields
	'''
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
		self.passive_port = None
		self.verbose = False
		self.listener = FTPListener(self.sport, self.dport, self.dst)
		self.listen_thread = Thread(target = self.listener.listen)
		self.listen_thread.start()
		self.passive_obj = None

	'''
		send_syn: sends SYN packet.
	'''
	def send_syn(self):
		ip = IP(dst=self.dst)
		syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
		pkt = ip/syn
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	'''
		send_pkt: Puts packet on the wire
	'''
	def send_pkt(self, pkt):
		seq_next = self.listener.next_seq 
		while self.listener.next_seq == seq_next:
			send(pkt, verbose=self.verbose)
			sleep(1)
		return

	'''
		handshake: Initialize handshake
	'''
	def handshake(self):
		self.send_syn()


	'''
		get_next_ack: Update the next_ack based on segment length of recieved packet.
	'''
	def get_next_ack(self, pkt):
		total_len = pkt.getlayer(IP).len
		ip_hdr_len = pkt.getlayer(IP).ihl * 32 / 8
		tcp_hdr_len = pkt.getlayer(TCP).dataofs * 32 / 8
		ans = total_len - ip_hdr_len - tcp_hdr_len
		return (ans if ans else 1)

	'''
		passive: send PASV command and initialize passive port
	'''
	def passive(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'AP'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		cmd = "PASV\r\n"
		pasv = pkt/cmd
		self.send_pkt(pasv)
		self.passive_port = self.listener.get_passive_port()

	'''
		manage_passive: if new passive connection is created, respective helper functions called.		
	'''
	def manage_passive(self, command):
		passive = FTPPassive(self.dst, self.passive_port)
		passive.handshake()
		base_cmd = command.split('\r\n')[0]
		cmd = base_cmd.split(' ')[0]
		if cmd == 'STOR':
			passive.sendfile(base_cmd.split(' ')[1])
		if cmd == 'RETR':
			recv_thread = Thread(target=passive.recvfile, args=(base_cmd.split(' ')[1], ))
			recv_thread.start()
		return passive

	'''
		close: closes the TCP connection. Issues found while closing. Need to be fixed
	'''
	def close(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.listener.next_seq
		pkt[TCP].ack = self.listener.next_ack
		send(pkt, verbose=self.verbose)
		self.listen_thread.join()

	'''
		run_command: sends the command and based on command, if it runs on passive mode, it creates an FTPPassive object.
	'''
	def run_command(self, command):
		if command == 'exit\r\n':
			self.close()
			return
		base_cmd = command.split('\r')[0].split(' ')[0]
		if base_cmd in cmd_passive:
			self.passive()
			self.passive_obj = self.manage_passive(command) 
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

	'''
		interactive: Takes input from user and sends it to server through run_command	
	'''
	def interactive(self):
		command = ""
		while True:
			sys.stdout.write(">> ")
			command = raw_input() + '\r\n'
			if command == 'exit\r\n':
				self.close()
				return
			else:
				self.run_command(command)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-6', '--ipv6', help='User FTP on IPv6 network', action='store_true')
	parser.add_argument('-u', '--user', help='Username for FTP login', nargs=1, type=str, required=True)
	parser.add_argument('-l', '--passwd', help='Password for FTP login', nargs=1, type=str, required=True)
	parser.add_argument('-i', '--ipaddr', help='FTP server IP address', nargs=1, type=str, required=True)
	parser.add_argument('-p', '--port', help='Port address of FTP server', nargs=1, type=int, required=True)
	args = parser.parse_args()

	if args.ipv6:
		IP = IPv6

	client = FTPClient(args.ipaddr[0], args.port[0])
	client.handshake()
	client.run_command('USER ' + args.user[0] + '\r\n')
	client.run_command('PASS ' + args.passwd[0] + '\r\n')
	client.interactive()