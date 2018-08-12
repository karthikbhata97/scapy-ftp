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


local_ip = socket.gethostbyname(socket.gethostname())

class FTP_Passive_Listener:
	# Initializes the fields
	def __init__(self, src, dst, sport):
		self.src = src
		self.dst = dst
		self.sport = sport
		self.dport = None
		self.data_share = Queue([100])
		self.next_seq = 0
		self.next_ack = None
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
		self.basic_pkt = IP(src=self.src, dst=self.dst)/TCP(sport=self.sport)
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
			and pkt.haslayer(TCP) and pkt[TCP].dport == self.sport:
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

		if pkt[TCP].flags & self.tcp_flags['TCP_SYN']:
			self.next_ack = pkt[TCP].seq + 1			
			dst = pkt[IP].src
			src = pkt[IP].dst
			self.dport = pkt[TCP].sport
			self.basic_pkt[TCP].dport = self.dport 
			ackno = pkt[TCP].seq + 1
			seqno = 0 # use random
			synack = IP(src=src, dst=dst)/TCP(sport=self.sport, dport=self.dport, flags='SA', seq=seqno, ack=ackno)
			reply = None
			while not reply:
				reply = sr1(synack, timeout=1, verbose=self.verbose)
			seqno += 1

		if pkt[TCP].flags & self.tcp_flags['TCP_ACK']:
			self.next_seq = pkt[TCP].ack
		if Raw in pkt:
			self.data_share.put(pkt[Raw].load)


	# Starts listening on the wire
	def run(self):
		sniff(prn=self.manage_resp, lfilter=self.sniff_filter, stop_filter=self.finish)

	def command(self, command , cwd):
		self.__currdir = cwd
		cmd = command.split(' ')[0]
		if cmd == "LIST":
		      k = ""
	 	      print 'list:', self.__currdir
  	      	      for t in os.listdir(self.__currdir):
  	          	k+=self.toListItem(os.path.join(self.__currdir,t)) + '\n'
  	      	      self.send_data(k+'\r\n')                    
		      self.close()
		      return
		
		if cmd == "STOR":
			with open(command.split(' ')[1], "w") as f:
				while True:
					if not self.data_share.empty():
						f.write(self.data_share.get())
					if self.data_share.empty():
						break
			self.close()

		if cmd == "RETR" :
			with open(command.split(' ')[1],"r") as f:
				data = f.read()
				chunks = [data[i:i+512] for i in range(0, len(data), 512)]
			for item in chunks:
				pkt = self.basic_pkt
				pkt[TCP].flags = 'AP'
				pkt[TCP].seq = self.next_seq
				pkt[TCP].ack = self.next_ack
				pkt = pkt/Raw(load=item)
				print pkt
				self.send_pkt(pkt)
			self.close()

		else:
		      return


	def close(self):
		pkt = self.basic_pkt
		pkt[TCP].flags = 'FA'
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		sr1(pkt, verbose=self.verbose)	




      	def toListItem(self,fn):
    	    st=os.stat(fn)
    	    fullmode='rwxrwxrwx'
    	    mode=''
    	    for i in range(9):
    	        mode+=((st.st_mode>>(8-i))&1) and fullmode[i] or '-'
    	    d=(os.path.isdir(fn)) and 'd' or '-'
    	    ftime=time.strftime(' %b %d %H:%M ', time.gmtime(st.st_mtime))
    	    return d+mode+' 1 user group '+str(st.st_size)+ftime+os.path.basename(fn)
			
	# Put the reply into a packet
	def send_data(self, data):
		pkt = self.basic_pkt/Raw(load=data)
		self.send_pkt(pkt)

	# send the packet
	def send_pkt(self, pkt):
		pkt[TCP].flags = 'PA'
		pkt[TCP].seq = self.next_seq
		pkt[TCP].ack = self.next_ack
		while self.next_seq == pkt[TCP].seq:
			sr1(pkt, timeout=1, verbose=self.verbose)
				


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
	__rest = False
	__rename_ready = False
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
	    'specify_filename':'421 Specify Filename.\r\n',
	    'dir_changed_root': '250 Directory changed to root.\r\n',
	    'path_not_found': '550 Path not found.Directory not changed\r\n',
	    'file_not_found': '550 file_not_found in Directory \r\n', 	
	    'path_not_dir': '550 Path is not a directory.Directory not changed\r\n',
	    'use_pasv': '425 Use PASV or PORT first.\r\n',
	    'open_data_conn': '150 Opening data connection.\r\n',
	    'transfer_complete': '226 Transfer complete.\r\n',
	    'dir_list': '150 Here comes the directory listing.\r\n',
	    'pasv_mode': '227 Entering Passive Mode (%s,%u,%u).\r\n',
	    'dir_send':'226 Directory send OK.\r\n',
	    'dir_create':'257 Directory created.\r\n',
	    'dir_delete':'250 Directory deleted.\r\n',
	    'not_allowed':'450 Not allowed.\r\n',
	    'file_delete':'250 File deleted.\r\n',
	    'rename_from':'350 Ready.\r\n',
	    'rename_to':'250 File Renamed.\r\n',

  	}

	# initialize the fields
	def __init__(self, src, dst, sport, dport, seqno, ackno):
		self.src = src
		self.dst = dst
		self.sport = sport
		self.dport = dport
		self.s = seqno
		self.a = ackno
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

	def USER(self,cmd):
		try:
			self.user = cmd.split(' ')[1]
		except:
			self.send_data(self.__resp['cmd_error'])
			return
		self.send_data(self.__resp['username_ok'])

	def PASS(self,cmd):
		try:
			self.passwd = cmd.split(' ')[1]
		except:
			self.send_data(self.__resp['cmd_error'])
			return
		self.send_data(self.__resp['password_ok'])


        def LIST(self,cmd):
	      self.send_data(self.__resp['dir_list'])	     
	      self.passive_listener.command(cmd,self.__currdir)
	      self.passive_listener_thread.join()
	      self.send_data(self.__resp['dir_send'])
	      return

	def STOR(self,cmd):
	     self.send_data(self.__resp['open_data_conn'])
	     self.passive_listener.command(cmd,self.__currdir)	
 	     self.passive_listener_thread.join()
	     self.send_data(self.__resp['transfer_complete'])
	     return	

	def RETR(self,cmd):
	     self.send_data(self.__resp['open_data_conn'])
	     self.passive_listener.command(cmd,self.__currdir)	
 	     self.passive_listener_thread.join()
	     self.send_data(self.__resp['transfer_complete'])
	     return

	def MKD(self,cmd):
        	try:
		 	dn=os.path.join(cmd.split(' ')[1])
        		os.mkdir(dn)
		except:
			self.send_data(self.__resp['not_allowed'])
			return
		self.send_data(self.__resp['dir_create'])
		return

	def RMD(self,cmd):
		if os.path.isdir(cmd.split(' ')[1]):
			os.rmdir(fn)
			self.send_data(self.__resp['dir_delete'])
        	else:
			self.send_data(self.__resp['not_allowed'])
			return

	def DELE(self,cmd):
		fn=os.path.join(cmd.split(' ')[1])
		if os.path.exists(cmd.split(' ')[1]):
			os.remove(fn)
			self.send_data(self.__resp['file_delete'])
        	else:
			self.send_data(self.__resp['not_allowed'])
			return

	def CDUP(self,cmd):
		try:
			if not os.path.samefile(self.__currdir,self.__dirname):
				self.__currdir=os.path.abspath(os.path.join(self.__currdir,'..'))
			self.send_data(self.__resp['dir_changed_root'])
			return
		except:
			self.send_data(self.__resp['not_allowed'])
			return

	def PWD(self,cmd):
        	cwd=os.path.relpath(self.__currdir,self.__dirname)
       		if cwd=='.':
        	   	cwd='/'
		    	self.send_data('257 \"%s\"\r\n' % cwd)
		    	return
       		else:
            		cwd='/'+cwd
		    	self.send_data('257 \"%s\"\r\n' % cwd)
		    	return
		return

	def CWD(self,cmd):
        	 chwd=os.path.join(cmd.split(' ')[1])
	   	 if chwd=='/':
        		self.__currdir=self.__dirname
       		 elif chwd[0]=='/':
			if(os.path.isdir(os.path.join(self.__dirname,chwd[1:]))):
        			self.__currdir=os.path.join(self.__dirname,chwd[1:])
				self.send_data(self.__resp['dir_changed'])
				return
			else:
         			self.send_data(self.__resp['path_not_found'])
				return
            	 else:
		  	if(os.path.isdir(os.path.join(self.__currdir,chwd))):
 	       			self.__currdir=os.path.join(self.__currdir,chwd)
				self.send_data(self.__resp['dir_changed'])
				return
			else:
				self.send_data(self.__resp['path_not_found'])
				return
        def RNFR(self,cmd):
		try:    	    	
			self.rnfn=os.path.join(self.__currdir,cmd.split(' ')[1])
			print self.rnfn
			if os.path.exists(self.rnfn):       	
				self.send_data(self.__resp['rename_from'])
				self.__rename_from = True
			else:
				self.send_data(self.__resp['file_not_found'])	
		except:
			self.send_data(self.__resp['specify_filename'])	
			return

    	def RNTO(self,cmd):
		try:		
			if self.__rename_from:
        			fn=os.path.join(self.__currdir,cmd.split(' ')[1])
        			os.rename(self.rnfn,fn)
        			self.send_data(self.__resp['rename_to'])
				self.__rename_from = False
			else:
				self.send_data(self.__resp['not_allowed'])
		except:
			self.send_data(self.__resp['specify_filename'])	
		return
	
    	def PASV(self,cmd):
        	self.__pasv = True
		ip = self.src
        	port = 20
        	print 'open', ip, port
		self.send_data('227 Entering Passive Mode (%s,%u,%u).\r\n' %
        	        (','.join(ip.split('.')), port>>8&0xFF, port&0xFF))

   		self.passive_listener = FTP_Passive_Listener(self.src, self.dst, port)
		self.passive_listener_thread = Thread(target=self.passive_listener.run)
		self.passive_listener_thread.start()

		

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
