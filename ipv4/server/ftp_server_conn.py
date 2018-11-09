from tcp_connection import TCP_IPv6
from ftp_data_conn import FTPDataConnection
from threading import Thread
from random import randint
from os import path
from scapy.all import Raw


class FTPServerConnection:
    """
    Main class handling the server. Object is created for each connection.
    """
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
        'pasv_mode': '229 Entering Extended Passive Mode (|||%u|)\r\n',
        'active_mode': '200 EPRT command successful.\r\n',
    }

    # initialize the fields
    def __init__(self, src, dst, sport, dport, seqno, ackno):
        """
        Initializes the src, dst parameters.
        """
        self.src = src
        self.dst = dst

        self.sport = sport
        self.dport = dport

        self.tcp_conn = TCP_IPv6(src, dst, sport, dport, seqno, ackno)
        self.tcp_conn.listener.connection_open = True

        
    def run(self):
        self.send_data(self.__resp['welcome'])

        data_share = self.tcp_conn.listener.data_share
        while not self.__finish:

            if not data_share.empty():
                cmd = data_share.get().strip().decode('utf-8')
                self.command(cmd)

    
    def send_data(self, data):
        self.tcp_conn.send_data(Raw(load=data))


    def command(self, cmd):
        """
        Accepts command and calls the corresponding function handler.
        """
        print ('command %s recieved' % (cmd,))

        def default_resp(cmd):
            self.send_data('Not yet implemented or Invalid query\r\n')

        action = getattr(self, cmd.split(' ')[0], default_resp)
        action(cmd)

    def close(self):
        self.tcp_conn.close()
        self.__finish = True
        print('Connection closed')

    """
    All the following are the handlers for each of the commands.
    New functions can be simply added to support the corresponding command.
    """
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


    def EPSV(self, cmd):
        self.__pasv = True
        port = randint(1024, 65535)

        self.data_conn = FTPDataConnection(self.src, self.dst, port, None)

        self.send_data(self.__resp['pasv_mode'] % (port,))


    def EPRT(self, cmd):
        cmd = cmd.split('|')

        dst = cmd[2]

        dport = int(cmd[3])
        # sport = randint(1024, 65535)

        self.data_conn = FTPDataConnection(self.src, dst, 20, dport)
        self.data_conn.run_active()

        self.send_data(self.__resp['active_mode'])


    def LIST(self, cmd):

        self.send_data(self.__resp['dir_list'])

        self.data_conn.LIST(cmd, self.__currdir)

        self.send_data(self.__resp['transfer_complete'])

        if self.__pasv:
            self.__pasv = False


    def RETR(self, cmd):

        cmd = cmd.split(' ')

        filename = self.__currdir + '/' + cmd[1]
        filename_abs = path.abspath(filename)

        if len(filename_abs.split(self.__dirname)) == 1:
            self.send_data(self.__resp['not_file'] % (cmd[1],))
            self.data_conn.close()
            return

        self.send_data(self.__resp['open_data_conn'])
        self.data_conn.RETR(cmd, filename_abs)
        self.send_data(self.__resp['transfer_complete'])
        
        if self.__pasv:
            self.__pasv = False


    def STOR(self, cmd):
        filename = self.__currdir + '/' + cmd.split(' ')[1]

        filename_abs = path.abspath(filename)

        if len(filename_abs.split(self.__dirname)) == 1:
            self.send_data(self.__resp['not_file'] % (cmd[1],))
            self.data_conn.close()
            return

        with open(filename_abs, 'w') as f:
            f.write('')

        self.send_data(self.__resp['open_data_conn'])
        self.data_conn.STOR(cmd, filename_abs)
        self.send_data(self.__resp['transfer_complete'])

        if self.__pasv:
            self.__pasv = False
            