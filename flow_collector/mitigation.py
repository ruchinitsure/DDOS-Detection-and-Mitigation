"""
POX component for DOS mitigation.
Add this file in pox/ext folder.
run pox controller as ./pox.py mitgation
"""

from entropy_detection import MitigateAttack
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
import requests, json, signal
from pox.lib.revent import *

# Create a logger for this component
log = core.getLogger()

class Mitigation(EventMixin):
    
    def __init__(self) -> None:
        self.listenTo(core)
        self.listenTo(core.EntropyDetection)
        core.openflow.addListeners(self)
        self.dpids = set()
    
    def _handle_MitigateAttack(self, event):
        
        #extract the arguments to the event
        suspected_src = event.flow_entries[0]
        victim_dst = event.flow_entries[1]
        mac_src = event.flow_entries[2]
        mac_dst = event.flow_entries[3]

        #form the flow_mod message
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD, priority=of.OFP_DEFAULT_PRIORITY)
        msg.match = of.ofp_match()
        msg.match.dl_type = 0x800
        msg.match.nw_proto = 17
        msg.match.nw_dst = IPAddr(victim_dst)
        
        if(suspected_src != ""):
            msg.match.nw_src = IPAddr(suspected_src)
        
        msg.match.dl_src = EthAddr(mac_src)
        msg.match.dl_dst = EthAddr(mac_dst)

        msg.match.tp_src = 80
        msg.match.tp_dst = 1
        
        msg.actions = [] #drop
        msg.idle_timeout = 60

        #install within all switches
        for dpid in self.dpids:
            core.openflow.sendToDPID(dpid, msg)
    
    def _handle_ConnectionUp(self, event):
        log.info("connected to {}".format(event.dpid))
        self.dpids.add(event.dpid)
    
    def _handle_UpEvent(self, event):
        log.info("Mitigation Module running.")

def launch():
    core.registerNew(Mitigation)