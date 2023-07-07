# -*- coding: utf-8 -*-
"""
Created on Wed Jan 11 13:44:13 2023

@author: Ramprasad
"""

import socket                   
import sys
from uuid import getnode as get_mac
import random

#MAC ADDRESS
mac = get_mac()
mac_default =':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

dur=random.randint(3600, 86400)
if (len(sys.argv) >1):
    if (sys.argv[1] == "-m"):
        mac = str(sys.argv[2])
    else:
        mac = mac_default
#else:
  #  print "Please specify command line args as ./client.py -m \"MAC_addr\""
  #  sys.exit(1)
        

#print mac

def request_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x0C, 0x29, 0xDD]) 
        CHADDR2 = bytes([0x5C, 0xA7, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53 , 1 , 3])
        DHCPOptions2 = bytes([50 , 4 , 0xC0, 0xA8, 0x01, 0x64])
        DHCPOptions3 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01])
	
        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 +  DHCPOptions3

        return package


print("DHCP client is starting...\n")
s=str(input("Enter The Department Name for which the host should be allocated:"))

port = 1452
my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.bind(('', 0))
my_socket.settimeout(100)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
print("DHCP Discovery Sent..");
my_socket.sendto(b"F8:D0:90:9D:68:16", ('<broadcast>' ,port))



#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.bind(('', 0))
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#server_address = ('<broadcast>', 45555)

#s.connect((host, port))
#s.send("F8:D1:90:80:65:A8")

data, address = my_socket.recvfrom(1024)
print("Receive DHCP offer.")
#print(data)

print("Send DHCP request.")
data =request_get();
my_socket.sendto(data, address)
        
data,address = my_socket.recvfrom(1024)
print("Receive DHCP ACK.\n")
st=str(data)
n=len(st) 
print("IP address Allocated is :",st[2:n-1])
print("The IP address can be used for the Duration:",dur,"Seconds")
   
    #show_message('message from :'+ str(address[0]) , message)
    #data = my_socket.recv(1024)
    #print('data=%s', (data))
    

my_socket.close()
