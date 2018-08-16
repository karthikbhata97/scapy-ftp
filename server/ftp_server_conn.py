from scapy.all import *
from threading import Thread
from ftp_listener import FTPListener
from os import path
from ftp_passive_server import FTPPassiveServer
from random import randint

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
        self.listener_thread = Thread(target=self.listener.listen)
        self.listener_thread.start()

    # Run the commands
    def command(self, cmd):
        print 'command %s recieved' % (cmd,)

        def default_resp(cmd):
            self.send_data('Not yet implemented or Invalid query\r\n')

        action = getattr(self, cmd.split(' ')[0], default_resp)
        action(cmd)

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

        print 'Connection closed'


    def close(self):
        """
        Close TCP connection.
        """
        pkt = self.basic_pkt
        pkt[TCP].flags = 'FA'
        pkt[TCP].seq = self.listener.next_seq
        pkt[TCP].ack = self.listener.next_ack
        send(pkt, verbose=self.verbose)
        self.listener_thread.join()
        self.__finish = True

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


    def QUIT(self, cmd):
        self.send_data(self.__resp['goodbye'])
        self.close()

    
    def PWD(self, cmd):
        cdir = self.__currdir.split(self.__dirname, 1)[1] + '/'
        self.send_data(self.__resp['curr_dir'] % (cdir,))


    def CWD(self, cmd):
        dest_dir = self.__dirname + '/' + cmd.split('CWD ', 1)[1]

        if path.isdir(dest_dir):
            dest_dir_abs = path.abspath(dest_dir)
            
            if len(dest_dir_abs.split(self.__dirname)) == 1:
                self.send_data(self.__resp['path_not_found'])
            else:
                self.__currdir = path.abspath(dest_dir)
                self.send_data(self.__resp['dir_changed'])

        else:
            self.send_data(self.__resp['path_not_found'])


    def TYPE(self, cmd):
        self.__type = cmd.split(' ')[1]
        self.send_data(self.__resp['type_set'] % (self.__type,))


    def PASV(self, cmd):
        self.__pasv = True
        port = randint(1024, 65535)
        p_upper = (port >> 8) & 0xff
        p_lower = port & 0xff
        dst = ','.join(self.src.split('.'))

        self.passive_obj = FTPPassiveServer(self.src, self.dst, port, None)
        self.passive_thread = Thread(target=self.passive_obj.run)
        self.passive_thread.start()

        print port
        self.send_data(self.__resp['pasv_mode'] % (dst, p_upper, p_lower))


    def LIST(self, cmd):

        if not self.__pasv:
            self.send_data('Active mode not yet implemented\r\n')
            return

        self.send_data(self.__resp['dir_list'])

        self.passive_obj.LIST(cmd, self.__currdir)

        self.send_data(self.__resp['transfer_complete'])
        self.__pasv = False


    def RETR(self, cmd):
        if not self.__pasv:
            self.send_data('Active mode not yet implemented\r\n')
            return

        cmd = cmd.split(' ')

        filename = self.__currdir + '/' + cmd[1]
        filename_abs = path.abspath(filename)

        if len(filename_abs.split(self.__dirname)) == 1:
            self.send_data(self.__resp['not_file'] % (cmd[1],))
            self.passive_obj.close()
            return

        self.send_data(self.__resp['open_data_conn'])
        self.passive_obj.RETR(cmd, filename_abs)
        self.send_data(self.__resp['transfer_complete'])
        

    def STOR(self, cmd):
        filename = self.__currdir + '/' + cmd.split(' ')[1]

        filename_abs = path.abspath(filename)

        if len(filename_abs.split(self.__dirname)) == 1:
            self.send_data(self.__resp['not_file'] % (cmd[1],))
            self.passive_obj.close()
            return

        with open(filename_abs, 'w') as f:
            f.write('')

        self.send_data(self.__resp['open_data_conn'])
        self.passive_obj.STOR(cmd, filename_abs)
        self.send_data(self.__resp['transfer_complete'])