from ftp_client import FTPClient
import argparse
import netifaces as ni
import random
import sys


if __name__ ==  '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--iface', help='Interface name', nargs=1, type=str, required=True)
    arg_parser.add_argument('-i', '--host', help='Destiantion IP', nargs=1, type=str, required=True)
    arg_parser.add_argument('-p', '--port', help='Destination port', nargs=1, type=int, required=True)

    args = arg_parser.parse_args()

    try:
        ipaddr = ni.ifaddresses(args.iface[0])[ni.AF_INET6][0]['addr']
        ipaddr = ipaddr.split('%')[0]
    except:
        print ('Failed to fetch IP address of given interface')
        sys.exit(-1)

    src = ipaddr
    dst = args.host[0]
    sport = random.randint(1024, 65535)
    dport = args.port[0]

    client = FTPClient(src, dst, sport, dport)

    client.run_command("USER testftp")
    client.run_command("PASS testftp")
    # client.quit()

    cmd = ""
    while cmd != "QUIT":
        cmd = input()

        client.run_command(cmd)
    
    client.quit()