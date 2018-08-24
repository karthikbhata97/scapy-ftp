from scapy.all import *
from ftp_listener import FTPListener
from ftp_passive import FTPPassive
from time import sleep
from threading import Thread


class FTPClient:
    """
    Main client class takes care of eshtablishing connection and run commands.
    """

    cmd_passive = ['LIST', 'RETR', 'STOR']
    cmd_sender = ['STOR']

    def __init__(self, dst, sport, dport, interact=True, logfile=None):
        """
        Initializes destination IP and Port for the connection.
        dst (str): Destination IP
        sport (int): Source port
        dport (int): Destination port
        interact (bool): uses print to output to console # TODO use logger
        logfile (str): Incase of logging output into a file
        """
        self.sport = sport
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
        self.interact = interact
        self.logfile = logfile

        self.listener = FTPListener(self.sport, self.dport, self.dst, interact=self.interact, logfile=self.logfile)
        self.listen_thread = Thread(target = self.listener.listen)
        self.listen_thread.start()
        self.passive_obj = None


    def send_syn(self):
        """
        Sends syn packet and waits for acknowledgement.
        """
        ip = IP(dst=self.dst)
        syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.listener.next_seq, ack=self.listener.next_ack)
        pkt = ip/syn
        seq_next = self.listener.next_seq 
        while self.listener.next_seq == seq_next:
            send(pkt, verbose=self.verbose)
            sleep(1)
        return


    def send_pkt(self, pkt):
        """
        Sends a packet and waits for acknowledgement.
        """
        seq_next = self.listener.next_seq 
        while self.listener.next_seq == seq_next:
            send(pkt, verbose=self.verbose)
            sleep(1)
        return


    def handshake(self):
        """
        Initializes handshake by calling send_syn
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


    def passive(self):
        """
        Initializes passive mode by sending PASV command.
        """
        pkt = self.basic_pkt
        pkt[TCP].flags = 'AP'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        cmd = "PASV\r\n"
        pasv = pkt/cmd
        self.send_pkt(pasv)
        self.passive_port = self.listener.get_passive_port()


    def manage_passive(self, command):
        """
        Helper function to take care of passive commands.
        """
        passive = FTPPassive(self.dst, self.passive_port, interact=self.interact, logfile=self.logfile)
        passive.handshake()
        base_cmd = command.split('\r\n')[0]
        cmd = base_cmd.split(' ')[0]
        if cmd == 'STOR':
            passive.sendfile(base_cmd.split(' ')[1])
        if cmd == 'RETR':
            recv_thread = Thread(target=passive.recvfile, args=(base_cmd.split(' ')[1], ))
            recv_thread.start()
        if cmd == 'LIST':
            recv_thread = Thread(target=passive.recvfile, args=(None, ))
            recv_thread.start()
        return passive


    def close(self):
        """
        Close TCP connection.
        """
        pkt = self.basic_pkt
        pkt[TCP].flags = 'FA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        send(pkt, verbose=self.verbose)
        self.listen_thread.join()


    def run_command(self, command):
        """
        Takes command and sends it on the wire. If it is a command in passive mode,
        creates a passive connection.
        """
        if command == 'exit\r\n':
            self.close()
            return
        base_cmd = command.split('\r')[0].split(' ')[0]
        if base_cmd in self.cmd_passive:
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


    def interactive(self):
        """
        Creates an interactive terminal to enter commands.
        """
        command = ""
        while True:
            sys.stdout.write(">> ")
            command = raw_input() + '\r\n'
            if command == 'exit\r\n':
                self.close()
                return
            else:
                self.run_command(command)
