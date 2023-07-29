#!/usr/bin/env python
import requests
import json
import signal

rt = 'http://127.0.0.1:8008'
name = 'icmp'

def sig_handler(signal,frame):
  requests.delete(rt + '/flow/' + name + '/json')
  exit(0)

signal.signal(signal.SIGINT, sig_handler)

flow = {'keys':'ipsource,ipdestination,macsource,macdestination',
        'value':'frames',
        'log':True}
        
r = requests.put(rt + '/flow/' + name + '/json',data=json.dumps(flow))

flowurl = rt + '/flows/json?name=' + name + '&maxFlows=10&timeout=20'
flowID = -1

while 1 == 1:
    
    r = requests.get(flowurl + "&flowID=" + str(flowID))
    
    if r.status_code != 200: 
        break
    
    flows = r.json()
    
    if len(flows) == 0: 
        continue
    
    flowID = flows[0]["flowID"]
    flows.reverse()

    for f in flows:
        
        flow_id = str(f['flowID'])
        src_ip, dest_ip, src_mac, dest_mac = f['flowKeys'].split(',')
        datasource = str(f['dataSource'])
        flow_name = f['name']
        
        delimiter = "_SFLOW_"

        flow = "flow_id=" + flow_id + delimiter + "src_ip=" + src_ip + delimiter + "dest_ip=" + dest_ip + delimiter + "src_mac=" + src_mac + delimiter + "dest_mac=" + dest_mac + delimiter + "flow_name=" + flow_name + "\n\n"

        with open("data.txt", "a") as data_file:
            data_file.write(flow)

        print(flow)

