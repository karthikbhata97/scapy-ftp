from ftp_client import FTPClient
import argparse
import netifaces as ni
import random
import sys
from threading import Thread


def fetch_commands(cmd_file, m, user, passwd):
    with open(cmd_file, 'r') as f:
        cmds = f.readlines()
    
    user_cmd = ['USER {}'.format(user)] * m
    passwd_cmd = ['PASS {}'.format(passwd)] * m
    quit_cmd = ['QUIT'] * m

    all_commands = [user_cmd, passwd_cmd]

    for line in cmds:
        line = line.strip()
        c = line.split(',')
        if len(c) != m:
            continue

        all_commands.append(c)

    all_commands.append(quit_cmd)
    return all_commands


def manage_multiple(src, dst, sport, dport, user, passwd, m, cmd_file):

    commands = fetch_commands(cmd_file, m, user, passwd)

    connections = []
    for i in range(m):
        connections.append(FTPClient(src, dst, sport[i], dport, logfile='ftp-{}.log'.format(i)))

    threads = []
    for cmd in commands:
        print('Running: ', cmd)
        for i in range(m):
            t = Thread(target=connections[i].run_command, args=(cmd[i],))
            t.start()
            threads.append(t)
            with open('ftp-{}.log'.format(i), 'a') as f:
                f.write('>> {}\n'.format(cmd[i]))

        
        for i in range(m):
            threads[i].join()

        print('Done')

        threads = []

    for i in range(m):
        connections[i].quit()

    return


if __name__ ==  '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--iface', help='Interface name', nargs=1, type=str)
    arg_parser.add_argument('-i', '--host', help='Destiantion IP', nargs=1, type=str, required=True)
    arg_parser.add_argument('-p', '--port', help='Destination port', nargs=1, type=int, required=True)
    arg_parser.add_argument('-u', '--user', help='Username for FTP', nargs=1, type=str, required=True)
    arg_parser.add_argument('-l', '--passwd', help='Password for the FTP', nargs=1, type=str, required=True)
    arg_parser.add_argument('-m', '--multiple', help='Multiple connection mode', nargs=1, type=int)
    arg_parser.add_argument('-c', '--cmd_file', help='Command file', nargs=1, type=str)
    arg_parser.add_argument('-I', '--source_ip', help='Source IP address', nargs=1, type=str)
    arg_parser.add_argument('-P', '--source_port', help='Source port', nargs=1, type=int)


    args = arg_parser.parse_args()

    if args.iface:
        try:
            ipaddr = ni.ifaddresses(args.iface[0])[ni.AF_INET][0]['addr']
            ipaddr = ipaddr.split('%')[0]
        except:
            print ('Failed to fetch IP address of given interface')
            sys.exit(-1)
    elif args.source_ip:
        ipaddr = args.source_ip[0]
    else:
        print('Specify one of Source IP or Interface')

    if args.source_port:
        portaddr = args.source_port[0]
    else:
        portaddr = random.randint(1024, 65535)
        
    src = ipaddr
    dst = args.host[0]
    sport = portaddr
    dport = args.port[0]

    username = args.user[0]
    password = args.passwd[0]

    if not args.multiple:
        client = FTPClient(src, dst, sport, dport)

        client.run_command("USER %s" % (username,))
        client.run_command("PASS %s" % (password,))
        # client.quit()
        client.interactive()
    else:
        m = args.multiple[0]
        if not args.cmd_file:
            print('Give command file with -c argument')
            sys.exit(-1)
        
        cmd_file = args.cmd_file[0]

        sport = []
        while len(sport) < m:
            p = random.randint(1024, 65535)
            if p not in sport:
                sport.append(p)

        manage_multiple(src, dst, sport, dport, username, password, m, cmd_file)
