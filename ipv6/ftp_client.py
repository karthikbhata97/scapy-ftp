from scapy.all import *
from tcp_connection import TCP_IPv6
from threading import Thread
import sys


class FTPClient:

    __passive_cmd = ['LIST', 'STOR', 'RETR']

    def __init__(self, src, dst, sport, dport, verbose=False, logfile=None):

        self.tcp_connection = TCP_IPv6(src, dst, sport, dport)
        
        self.tcp_connection.handshake()

        self.close = False

        self.logfile = logfile

        self.logger_thread = Thread(target=self.logger)
        self.logger_thread.start()

        self.passive_port = None
        self.passive_mode = False


    def run_passive(self, cmd):
        cmd = cmd.split(' ')
        data_share = self.passive_connection.listener.data_share

        if cmd[0] == 'LIST':
            while self.passive_mode:
                if not data_share.empty():
                    print (data_share.get().decode('utf-8'))

        elif cmd[0] == 'RETR':
            filename = cmd[1]
            with open(filename, 'w') as f:
                while self.passive_mode:
                    if not data_share.empty():
                        f.write(data_share.get().decode('utf-8'))

        elif cmd[0] == 'STOR':
            filename = cmd[1]
            with open(filename, 'r') as f:
                data = f.read()

            data_chunks = [data[i:i+512] for i in range(0, len(data), 512)]
            for item in data_chunks:
                stor_data = Raw(load=item)
                self.passive_connection.send_data(stor_data)

        else:
            print (cmd, 'No such command')
                
        self.passive_connection.close()


    def run_command(self, cmd):
        if cmd.split(' ')[0] in self.__passive_cmd:
            self.send_data('EPSV\r\n')
            while not self.passive_port:
                pass

            dport = self.passive_port
            sport = random.randint(1024, 65535)

            self.passive_connection = TCP_IPv6(self.tcp_connection.src, self.tcp_connection.dst, sport, dport)
            self.passive_connection.handshake()
            self.passive_mode = True

            pasv_thread = Thread(target=self.run_passive, args=(cmd,))
            pasv_thread.start()
            cmd = cmd + '\r\n'
            self.send_data(cmd)

            self.passive_mode = False
            self.passive_port = None
            pasv_thread.join()
        else:
            cmd = cmd + '\r\n'
            self.send_data(cmd)


    def send_data(self, data):
        raw = Raw(load=data)
        
        self.tcp_connection.send_data(raw)


    def logger(self):
        data_share = self.tcp_connection.listener.data_share
        while not self.close:
            if not data_share.empty():
                data = data_share.get().decode('utf-8')

                if self.logfile:
                    with open(self.logfile, 'w') as f:
                        f.write(data)
                else:
                    sys.stdout.write(data)

                if data[:3] == '229':
                    self.passive_port = int(data.split('|||')[1].split('|')[0])


    def quit(self):
        self.close = True
        self.logger_thread.join()
        self.tcp_connection.close()