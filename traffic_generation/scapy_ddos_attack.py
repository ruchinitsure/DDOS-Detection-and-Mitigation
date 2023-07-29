import random
import sys
from os import popen
import logging
from pyrfc3339 import generate
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
import time
import socket, struct

def generate_random_ip():

    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) 
    if(ip == '0.0.0.0' or ip == '255.255.255.255'):
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))) 
    return ip


def main(argv):

    destination_ip = argv[1]

    # interface ex :h1-eth0
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    i = 0
    k = 0

    while True:

        count = random.randint(10,20)
        
        if(k % 2 == 0):
            source_ip = generate_random_ip()
        
        i = 0 
       

        while i < count:
            try:
                packets = Ether() / IP(dst = destination_ip, src = source_ip) / UDP(dport = 1, sport = 80)
                print(repr(packets))
                sendp(packets, iface = interface.rstrip(), inter = 1)
                i = i + 1

            except(KeyboardInterrupt):
                sys.exit(0)
        
        k = k + 1

if __name__=="__main__":
    
    if (len(sys.argv) != 2):
        print("Requires destination ip address")
        sys.exit(0)

    main(sys.argv)