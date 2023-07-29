"""
A Flow collector POX component.
Add this file in pox/ext folder.
run pox controller as ./pox.py flow_collector
"""

# Import some POX stuff
from time import sleep
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


class FlowCollector(EventMixin):
    
    def __init__(self):
        
        self.rt = "http://localhost:8008"
        
        self.name = "icmp"
        self.file_name = "/home/akanksha/Desktop/DDoS-Detection-and-Mitigation/data.txt"
        
        self.flow = {
            'keys'  : 'ipsource,ipdestination,macsource,macdestination',
            'value' : 'frames',
            'log'   : True
        }

        self.listenTo(core)
    
    def start_collecting(self):
        
        r = requests.put(self.rt + '/flow/' + self.name + '/json',data=json.dumps(self.flow))
        flowurl = self.rt + '/flows/json?name=' + self.name + '&maxFlows=10&timeout=20'
        flowID = -1

        while 1 == 1:
            
            try:
                r = requests.get(flowurl + "&flowID=" + str(flowID))
            except:
                break

            if r.status_code != 200: 
                break
    
            flows = r.json()
            if len(flows) == 0: continue
            
            flowID = flows[0]["flowID"]
            flows.reverse()

            for f in flows:
                
                flow_id = str(f['flowID'])
                src_ip, dest_ip, src_mac, dest_mac = f['flowKeys'].split(',')
                datasource = str(f['dataSource'])
                flow_name = f['name']
                
                delimiter = "_SFLOW_"

                flow = "flow_id=" + flow_id + delimiter + "src_ip=" + src_ip + delimiter + "dest_ip=" + dest_ip + delimiter + "src_mac=" + src_mac + delimiter + "dest_mac=" + dest_mac + delimiter + "flow_name=" + flow_name + delimiter + "datasource=" + datasource + "\n\n"
                
                with open(self.file_name, "a") as data_file:
                    data_file.write(flow)
    
    def _handle_UpEvent(self, event):
        
        # Event handler called when POX goes into up state
        sleep(20)
        log.info("Flow collector running")
        self.start_collecting()
        return
    
    def _handle_DownEvent(self, event):
        log.info("Flow collecter stopped")
        requests.delete(self.rt + '/flow/' + self.name + '/json')
        return

def launch():
    core.registerNew(FlowCollector)

