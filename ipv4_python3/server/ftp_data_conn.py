from tcp_connection import TCP_IPv4
from scapy.all import Raw
from subprocess import check_output


class FTPDataConnection:

    def __init__(self, src, dst, sport, dport, verbose=False):

        self.src = src
        self.dst = dst

        self.sport = sport
        self.dport = dport

        self.verbose = verbose

        self.tcp_connection = TCP_IPv4(src, dst, sport, dport)
        print('data connection open')

    def run_active(self):
        self.tcp_connection.handshake()

    
    def send_data(self, data):
        chunk_sz = 512
        data_chunks = [data[i:i+chunk_sz] for i in range(0, len(data), chunk_sz)]
        
        for data in data_chunks:
            self.tcp_connection.send_data(Raw(load=data))


    def close(self):
        self.tcp_connection.close()
        print('Data connection closed')


    def LIST(self, cmd, currdir):
        """
        Helper function to handle LIST command.
        """
        dir_list = check_output(['ls', '-l', currdir]).decode('utf-8')
        dir_list = dir_list.split('\n', 1)[1]

        dir_list = dir_list.replace('\n', '\r\n')
        self.send_data(dir_list)
        self.close()


    def RETR(self, cmd, filename):
        """
        Helper function to handle RETR command.
        """
        with open(filename, 'r') as f:
            data = f.read()

        self.send_data(data)
        self.close()


    def STOR(self, cmd, filename):
        """
        Helper function to handle STOR command.
        """
        data_share = self.tcp_connection.listener.data_share

        while not self.tcp_connection.listener.dst_closed: 

            if not data_share.empty():
                data = data_share.get().decode('utf-8')
                with open(filename, 'a') as f:
                    f.write(data)

        self.close()