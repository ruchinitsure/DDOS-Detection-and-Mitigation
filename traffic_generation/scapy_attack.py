import sys
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
import time

def main(argv):
    source_ip = argv[1]
    destination_ip = argv[2]

    print("source = {0} and destination = {1}".format(source_ip, destination_ip))

    # interface ex :h1-eth0
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    while True:
        try:
            packets = Ether() / IP(dst = destination_ip, src = source_ip) / UDP(dport = 1, sport = 80)
            print(repr(packets))

            #send 10 packets per second
            sendp(packets, iface = interface.rstrip(), inter = 0.010)
            
        except(KeyboardInterrupt):
            sys.exit(0)


if __name__=="__main__":
    
    if (len(sys.argv) != 3):
        print("Requires source and destination ip address")
        sys.exit(0)

    main(sys.argv)