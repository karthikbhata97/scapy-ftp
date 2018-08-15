import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import argparse
from ftp_server import FTPServer


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', help='Port on which server runs', nargs=1, type=int, default=21)
    args = parser.parse_args()
    port = args.port[0]
    server = FTPServer(port)
    server.run()