import sys
import getopt
import time
from os import popen
import logging
from numpy import source
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import random


def generate_random_ip():
    first = 10
    second = 0 
    third = 0

    ip = ".".join([str(first), str(second), str(third), str(randrange(1,18))])

    return ip

def main(argv):    
    
    #open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    while True:

        destination_ip = generate_random_ip()
        count = random.randint(5, 10)
        sleep_time = random.randint(5, 10)

        print("sending {0} packets".format(count))
        
        while(count > 0):
            try:
                packet = Ether() / IP(dst = destination_ip) / UDP(dport = 80, sport = 2)
                print(repr(packet))

                #send  one packet per second
                sendp(packet, iface = interface.rstrip(), inter = 2)
                count -= 1
            except(KeyboardInterrupt):
                sys.exit(0)

        print("sleeping for {0} seconds".format(sleep_time))
        time.sleep(sleep_time)

if __name__ == '__main__':  
    main(sys.argv)
