#!/usr/bin/env python

from time import sleep
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

# Compile and run sFlow helper script
# - configures sFlow on OVS
# - posts topology to sFlow-RT
execfile('/home/akanksha/sflow-rt/extras/sflow.py') 

def NetworkTopo():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)
    
    info( '*** Add switches\n')
    
    #define number of switches and host
    n_switches = 6
    n_host = 4
    host_switches = 4

    #add switches
    switches = []
    for i in range(0, n_switches):
        switches.append(net.addSwitch('s%s' % (i+1), cls=OVSKernelSwitch))
        
    #add hosts
    hosts = []
    k = 1
    for j in range(0, host_switches):
        for i in range(0, n_host):
            hosts.append(net.addHost('h%s' % k, cls=Host, ip='10.0.0.%s'%k, defaultRoute=None))
            
            #create link between host and switch
            net.addLink(hosts[k-1], switches[j])

            k += 1

    hosts.append(net.addHost('h%s' % k, cls=Host, ip='10.0.0.%s'%k, defaultRoute=None))
    
    # linkear linkage between switches
    for i in range(0, host_switches):
        if i != host_switches -1:
            net.addLink(switches[i],  switches[i+1])

    # multi route links
    net.addLink(switches[0], switches[4])
    net.addLink(switches[5], switches[3])
    net.addLink(switches[4], switches[5])
    net.addLink(switches[4], switches[2])
    net.addLink(switches[5], switches[1])
    net.addLink(switches[5], hosts[k-1])

    net.start()
    info( '*** Configured switches and hosts\n')
    CLI(net) 
    net.stop()

if __name__ == "__main__":

    setLogLevel('info')
    NetworkTopo()
