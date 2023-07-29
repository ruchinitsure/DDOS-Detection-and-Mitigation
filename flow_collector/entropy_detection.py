"""
A packet analyzing POX component.
Add this file in pox/ext folder.
run pox controller as ./pox.py entropy_detection
"""

# Import some POX stuff

from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
import requests, json, signal
from pox.lib.revent import *
from collect_stats import CollectStats

# Create a logger for this component
log = core.getLogger()

#invoked when MitigationAttack event is raised
class MitigateAttack(Event):
    
    def __init__(self, arg) -> None:
        Event.__init__(self)
        self.flow_entries = arg


class EntropyDetection(EventMixin):
    
    _eventMixin_events = set([MitigateAttack,])

    def __init__(self, attack_type) -> None:
        self.listenTo(core)
        self.listenTo(core.FlowCollector)
        self.window_count = 1
        self.no_entropy_rounds = 0
        self.current_victim = ""
        self.data = []        
        self.mac_data = []
        self.attack_type = attack_type
   
    def _handle_WindowFull(self, event):
        
        print("entropy detection window : {0}".format(self.window_count))
        
        collect_stats = CollectStats()
        
        destination_count, src_dest_count, mac_ip = collect_stats.get_count(event.flow_list)
        
        print("mac address mapping : {0}\n".format(mac_ip))

        dynamic_threshold, window_entropy = collect_stats.get_adaptive_threshold_entropy(destination_count, src_dest_count)

        print("dynamic threshold : {0}\nwindow entropy : {1}\n".format(dynamic_threshold, window_entropy))

        if(dynamic_threshold > window_entropy):
    
            #calculate the victim destination for the window
            current_victim = collect_stats.find_victim(destination_count)
            
            #check if the victim is observed for first time
            if(self.no_entropy_rounds == 0):
                self.current_victim = current_victim

            #if same victim is observed for consecutive windows increment the no of entropy rounds
            if(current_victim == self.current_victim):
                self.no_entropy_rounds += 1
            else:
                self.data = []
                self.mac_data = []
                self.no_entropy_rounds = 1
                self.current_victim = current_victim
            
            self.data.append(src_dest_count)
            self.mac_data.append(mac_ip)

            if(self.no_entropy_rounds == 3):
                print("Attack detected on {0}".format(current_victim))
                # print("data : {0}\n".format(self.data))
                # print("mac data : {0}\n".format(self.mac_data))
                
                if(self.attack_type == 'DOS'):
                   
                    suspected_source = collect_stats.find_source(self.data, current_victim)
                    mac_src, mac_dst = collect_stats.find_mac_addr(self.mac_data, suspected_source, current_victim)

                    self.raiseEvent(MitigateAttack, [suspected_source, current_victim, mac_src, mac_dst])
                    
                    self.no_entropy_rounds = 0
                    
                elif(self.attack_type == 'DDOS'):
                    
                    #find attacker
                    suspected_source_mac = collect_stats.find_DDOS_source(self.mac_data)
                    mac_dst = collect_stats.find_dest_mac(self.mac_data, current_victim)

                    print("sources : {0}\n".format(suspected_source_mac))

                    if(len(suspected_source_mac) != 1):
                        print("More than one spoofed source found !!")
                    else:
                        self.raiseEvent(MitigateAttack, ["", current_victim, suspected_source_mac[0], mac_dst])

                self.data = []
                self.mac_data = []
                self.current_victim = ""

            print("No of entropy rounds : {0}\n".format(self.no_entropy_rounds))
        else :
            self.no_entropy_rounds = 0
            self.data = []
            self.mac_data = []
            self.current_victim = ""

        self.window_count += 1


def launch(attack_type="DOS"):

    core.registerNew(EntropyDetection, attack_type)