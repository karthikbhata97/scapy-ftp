import sys
import argparse
from ftp_client import FTPClient
from threading import Thread
import random
import signal


def signal_handler(signal, frame):
    print "Exiting..."
    sys.exit(0)


def fetch_commands(n):
    sys.stdout.write(">> ")
    cmd = raw_input()
    c = [cmd] * n
    if cmd == 'exit':
        return []
    return c

def run_cmd_multiple(connections, n, cmd_list):		
    threads = []
    for i in range(n):
        cmd = cmd_list[i] + '\r\n'
        with open(connections[i].logfile, 'a') as f:
            f.write(">>> {}".format(cmd))
        t = Thread(target=connections[i].run_command, args=(cmd,))
        t.start()
        threads.append(t)
    for i in range(n):
        threads[i].join()			

def manage_multiple(n, user, passwd, infile):
    ports = []
    for i in range(n):
        p = random.randint(1024, 65535)
        while p in ports:
            p = random.randint(1024, 65535)
        ports.append(p)
    connections = []
    for i in range(n):
        logfile = 'ftp-client-{}.log'.format(i)
        c = FTPClient(server_ip, ports[i], server_port, interact=False, logfile=logfile)
        c.handshake()
        connections.append(c)

    run_cmd_multiple(connections, n, ['USER ' + user] * n)
    run_cmd_multiple(connections, n, ['PASS ' + passwd] * n)

    cmds = []
    if infile:
        with open(infile, 'r') as f:
            cmds = f.read().split('\n')
        cmd_list = []
        for c in cmds:
            if c.strip():
                cmd_list.append(c.strip().split(','))
        cmd_list = cmd_list[::-1]

    while True:
        if infile:
            if not len(cmd_list):
                c = []
            else:
                c = cmd_list.pop()
        else:
            c = fetch_commands(n)
        # c += '\r\n'			
        
        print c

        if len(c) != n:
            if len(c):
                print "Insufficient commands {} for {} connections".format(','.join(c), n)
            for i in range(n):
                with open(connections[i].logfile, 'a') as f:
                    f.write('Exiting...\n\n')
                connections[i].close()
            return

        run_cmd_multiple(connections, n, c)
        


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', help='Username for FTP login', nargs=1, type=str, required=True)
    parser.add_argument('-l', '--passwd', help='Password for FTP login', nargs=1, type=str, required=True)
    parser.add_argument('-i', '--ipaddr', help='FTP server IP address', nargs=1, type=str, required=True)
    parser.add_argument('-p', '--port', help='FTP server port number', nargs=1, type=int, required=True)
    parser.add_argument('-m', '--multiple', help='Open multiple connections to FTP server', nargs=1, type=int)
    parser.add_argument('-c', '--command_file', help='Run commands from given file for multi connections. \
                        Each line has n(number of multiple connections) comma seperated FTP commands.', 
                        nargs=1, type=str)
    args = parser.parse_args()

    server_ip = args.ipaddr[0]
    server_port = args.port[0]
    client_port = random.randint(1024, 65535)

    if args.multiple:
        print "Multiple mode"
        num = args.multiple[0]
        infile = None
        if args.command_file:
            infile = args.command_file[0]
        manage_multiple(num, args.user[0], args.passwd[0], infile)
    else:
        client = FTPClient(server_ip, client_port, server_port)
        client.handshake()
        client.run_command('USER ' + args.user[0] + '\r\n')
        client.run_command('PASS ' + args.passwd[0] + '\r\n')
        client.interactive()