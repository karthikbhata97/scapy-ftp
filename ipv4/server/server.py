from ftp_server import FTPServer
import argparse
import netifaces as ni
import random
import sys


if __name__ ==  '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--iface', help='Interface name', nargs=1, type=str, required=True)
    # arg_parser.add_argument('-i', '--host', help='Destiantion IP', nargs=1, type=str, required=True)
    arg_parser.add_argument('-p', '--port', help='Destination port', nargs=1, type=int, required=True)

    args = arg_parser.parse_args()

    try:
        ipaddr = ni.ifaddresses(args.iface[0])[ni.AF_INET][0]['addr']
        ipaddr = ipaddr.split('%')[0]
    except:
        print ('Failed to fetch IP address of given interface')
        ipaddr = None

    src = ipaddr
    sport = args.port[0]

    server = FTPServer(src, sport)
    server.run() 