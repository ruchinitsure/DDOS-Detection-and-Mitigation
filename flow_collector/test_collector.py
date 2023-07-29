"""
A Flow collector POX component.
Add this file in pox/ext folder.
run pox controller as ./pox.py flow_collector
change the location of the file
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

#invoked on window full event is raised
class WindowFull(Event):
    
    def __init__(self, arg) -> None:
        Event.__init__(self)
        self.flow_list = arg


class FlowCollector(EventMixin):

    _eventMixin_events = set([WindowFull,])
    
    def __init__(self):
        
        self.rt = "http://localhost:8008"
        
        self.name = "traffic"
        self.file_name = "/home/akanksha/Desktop/DDoS-Detection-and-Mitigation/data.txt"
        
        self.flow = {
            'keys'  : 'ipsource,ipdestination,macsource,macdestination,udpsourceport,udpdestinationport',
            'value' : 'frames',
            'log'   : True
        }

        self.listenTo(core)
        self.window_size = 100
        self.count  = 0
        self.flow_list = []
    
    def start_collecting(self):
        
        r = requests.put(self.rt + '/flow/' + self.name + '/json',data=json.dumps(self.flow))
        flowurl = self.rt + '/flows/json?name=' + self.name + '&maxFlows=' + str(self.window_size) +'&timeout=30'
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
	
                print("count : {0}".format(self.count)) 

                #if window size is complete
                if self.count == self.window_size:
                    self.count  = 0
                    #raise the event and pass the list
                    self.raiseEvent(WindowFull, self.flow_list)
                    self.flow_list = []
            
                flowkey_dict = {}
                flowkey_dict['src_ip'],flowkey_dict['dest_ip'], flowkey_dict['src_mac'],flowkey_dict['dest_mac'] = f['flowKeys'].split(',')[:4]
                flowkey_dict['flow_id'] = f['flowID']
                flowkey_dict['datasource'] = f['dataSource']

                self.flow_list.append(flowkey_dict)
                self.count += 1
    
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

