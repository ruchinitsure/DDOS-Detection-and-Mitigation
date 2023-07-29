import os
import time
import random 

host_ip_addresses = [	'10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', 
			'10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8', 
			'10.0.0.9', '10.0.0.10', '10.0.0.11', '10.0.0.12',
			'10.0.0.13', '10.0.0.14', '10.0.0.15', '10.0.0.16', '10.0.0.17' ]
  
while(True):

    ip = random.sample(host_ip_addresses, 1)
    packet_size = random.randint(150, 200)
    count = random.randint(10, 20)
    sleep_time = random.randint(0,5)
    command = 'sudo hping3 --icmp --count '+ str(count) + ' --data ' + str(packet_size) + ' '+ " ".join(ip)
    os.system(command)
    time.sleep(sleep_time)

