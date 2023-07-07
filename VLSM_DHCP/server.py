# -*- coding: utf-8 -*-
"""
Created on Wed Jan 11 13:53:59 2023

@author: Ramprasad
"""

import sys
import os
import re
import socket
from math import *
from operator import itemgetter
import copy
import socket

ip=''
PORT = 1452
HOST = 'localhost'
allocation = {}
mac_map = {}
mac_ip_map = {}
deleted_labs = []
avl_ip_dr=[]
labs_info=[]
def avail_ip_addrs():
    n=30
    for k in labs_info:
        if k[0]=="REMAINING":
            n=k[1]
        else:
            n=30
    if "REMAINING" in allocation.keys():
        ip_dr=allocation["REMAINING"][0]
        avl_ip_dr.append(ip_dr)
        
        for i in range(1,n):
            s=avl_ip_dr[i-1]
            avl_ip_dr.append(get_next_ip_addr(s))
    else:
        print("There Are No Remaining Hosts.")
        print("IP Address taken new IP Address Data")
        strt=ip.split(".")
        if strt[0]=="15":
            ip_dr="16.220.0.0"
            for i in range(1,n):
                j=str(i)
                ip_d="16.220.0."+j
                avl_ip_dr.append(ip_d)
        else:
            for i in range(1,n):
                j=str(i)
                ip_d="15.220.0."+j
                avl_ip_dr.append(ip_d)
    #ip_dr="10.220.0.1"
    l=[]
    
def offer_get():
    OP = bytes([0x02])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64]) #192.168.1.100
    SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04]) 
    CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53 , 1 , 2]) # DHCP Offer
    DHCPOptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) #255.255.255.0 subnet mask
    DHCPOptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1 router
    DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) # DHCP server
        
    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package
def pack_get():
    OP = bytes([0x02])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
    SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
    CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04]) 
    CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
    CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00]) 
    CHADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53 , 1 , 5]) #DHCP ACK(value = 5)
    DHCPOptions2 = bytes([1 , 4 , 0xFF, 0xFF, 0xFF, 0x00]) #255.255.255.0 subnet mask
    DHCPOptions3 = bytes([3 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #192.168.1.1 router
    DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) #86400s(1 day) IP address lease time
    DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #DHCP server
	
    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR +YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

    return package  
def validate_CIDR(CIDR_format_string):

    valid_IP_regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    CIDR_format_string = CIDR_format_string.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]

    if not re.match(valid_IP_regex, ip):
        print ("Invalid IPv4 has been provided.")

    try:
        subnet_mask = int(subnet_mask)
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)

    if not subnet_mask < 33:
        print ("Invalid Subnet Mask has been provided.")
        sys.exit(1)



def convert_mask_to_ip(subnet_mask):
    
    # ex. 24 -> 255.255.255.0
    
    subnet_list = []
    for x in range(4): # creating list of four 0s
        subnet_list.append(0)
    
    #print (subnet_list)
    try:
        octets = int(subnet_mask / 8)  # how many octets of 255
    except TypeError as err:
        print ("Type Error for your Subnet Mask provided: {0}".format(err))
        sys.exit(1)

    if (octets <= 0):
        rem_subnet = 8 - subnet_mask
        #Fixed an int function
        subnet_list[0] = int(256 - pow(2,rem_subnet))

    else:
        for i in range(octets):
            subnet_list[i] = 255
        rem_subnet = 8 - (subnet_mask - 8 * octets)
        subnet_list[i+1] = int(256 - pow(2,rem_subnet))
    
    return subnet_list


def get_network_address(ip_addr,subnet_list):
    
    NA=[]
    for x in range(4):
        NA.append(0)
    
    # Convert list members to ints.
    for x in range(4):
        ip_addr[x] = int(ip_addr[x])
        subnet_list[x] = int(subnet_list[x])
    for x in range(4):
        
        # Logic: NA is obtained via ANDing the bits of ip address and the subnet
        
        NA[x] = ip_addr[x] & subnet_list[x]  # octet and subnetmask
    return NA


def get_broadcast_address(ip_addr, subnet_list):

    # Get broadcast address from ip and mask

    BA = []
    for x in range(4):
        BA.append(0)
    
    # Convert list members to ints.
    
    for x in range(4):
        ip_addr[x] = int(ip_addr[x])
        subnet_list[x] = int(subnet_list[x])
    
    for x in range(4):
        #Logic: You OR!
        BA[x] = (ip_addr[x]) | (255 - subnet_list[x])  # octet or wildcard mask
    return BA


def min_pow2(capacity):
    
    # how many bits do we need to borrow to cover number of hosts

    z = log(capacity, 2)  
    int_z = int(z)
    if z == int_z:
        return int_z
    else:
        return int(ceil(z))
    

def join(ip_addr):

    # Joiner for the IP

    addr = []
    for i in range(len(ip_addr)):
        addr.append(str(ip_addr[i]))
    #print addr
    addr =  ".".join(addr)

    return addr


def get_next_usable_addr(ipaddr, subnet_list):
    
    """
    Isn't this a duplicate of get_next_ip_addr(ipaddr)?
    """

    ipaddr = get_broadcast_address(ipaddr, subnet_list)
    
    for i in range(len(ipaddr)):
        last_digit = 3-i
        if ipaddr[last_digit] != 255:
            ipaddr[last_digit] += 1
            break
        else:
            ipaddr[last_digit] = 0
            if ipaddr[last_digit - 1] != 255:
                ipaddr[last_digit - 1] += 1
                break
    return ipaddr


def get_next_ip_addr(ipaddr):
    
    """
    Gives the next IPv4 addr.
    >>> get_next_ip_addr('10.220.65.66')
    >>> '10.220.65.67'
    """

    ipaddr = ipaddr.split('.')

    for i in range(len(ipaddr)):
        ipaddr[i] = int(ipaddr[i])

    for i in range(len(ipaddr)):
        last_digit = 3-i
        if ipaddr[last_digit] != 255:
            ipaddr[last_digit] += 1
            break
        else:
            ipaddr[last_digit] = 0
            if ipaddr[last_digit - 1] != 255:
                ipaddr[last_digit - 1] += 1
                break
    
    return join(ipaddr)


def assign_client_ip(lab, mac_addr):

    # Assigns an IP to the client in the given range for the lab.
    
    if mac_addr in mac_ip_map:
        dns = allocation[lab][4]
        print(dns)
        client_subnet = allocation[lab][3]
        #print "AAAA"
        #print mac_ip_map[mac_addr]
        #print client_subnet
        na = join(get_network_address(mac_ip_map[mac_addr].split("."),convert_mask_to_ip(int(client_subnet)) ))
        ba = join(get_broadcast_address(mac_ip_map[mac_addr].split("."),convert_mask_to_ip(int(client_subnet)) ))
        return mac_ip_map[mac_addr], client_subnet, dns, na, ba
    
    
    if mac_addr not in mac_ip_map:
        allocation[lab]="2.220.125.240"
        dns = allocation[lab][4]
        allocation[lab][2] = get_next_ip_addr(allocation[lab][2])
        client_ip = allocation[lab][2]
        client_subnet = allocation[lab][3]
        
        


        mac_ip_map.update({mac_addr: client_ip})

        na = join(get_network_address(mac_ip_map[mac_addr].split("."),convert_mask_to_ip(int(client_subnet)) ))
        ba = join(get_broadcast_address(mac_ip_map[mac_addr].split("."),convert_mask_to_ip(int(client_subnet)) ))
        return client_ip, client_subnet, dns, na , ba

    if get_next_ip_addr(allocation[lab][1]) == allocation[lab][2]:
        print("No more IP addresses are available")
        return None


def get_labs_info(file_content, subnet_mask):

    total_slots_given = int(pow(2, 32 - int(subnet_mask))) # Correct???
    total_slots_given=total_slots_given-2
    # Validate the type of "number of labs"
    try:
        num_of_labs = int(file_content[1])
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)

    # Get Capacity and MAC address objects for the labs
    capacity_of_labs = []
    labs = []
    labs_dict = {}

    # This part should be tested properly and I think "- 2" should not be there
    for i in range(2, 2+num_of_labs):
        this_line = file_content[i].split(':')
        if (int(this_line[1])+2) <= total_slots_given:
            labs_dict.update({str(this_line[0]): int(this_line[1])})

    for i in range(2+num_of_labs, len(file_content)):
        this_line = file_content[i].split('-')
        if str(this_line[1]) in labs_dict:
            mac_map.update({str(this_line[0]): str(this_line[1])})

    print("MAC ADDRESSES ")
    print("=========")
    print (mac_map)
    print ("=========\n\n")

    for key, value in labs_dict.items():
        labs.append(key)
        capacity_of_labs.append(int(value))
    bits = min_pow2(int(capacity_of_labs[0]) + 2)
    total_allocated=int(2*len(capacity_of_labs))
    for i in capacity_of_labs:
        bits = min_pow2(int(i) + 2)
        #print(i,2**bits)
        total_allocated=total_allocated+(2**bits)
    #print(sum(capacity_of_labs),2*len(capacity_of_labs),total_slots_given)
    #total_allocated = sum(capacity_of_labs) + int(2*len(capacity_of_labs))
    #print(min_pow2(total_allocated))
    # And, unkown lab should also be handled (TEST!!)
    if (total_slots_given - total_allocated) > 2:
        # Add UNKNOWN LABS to accomodate other people
        # Giving remaining slots to UNKNOWN
        labs.append('REMAINING')
        #print(total_slots_given-total_allocated-2)
        #total_slots_given-total_allocated-2
        capacity_of_labs.append(total_slots_given-total_allocated-2)

    labs_info = zip(labs, capacity_of_labs)
    #print("lab info")
    
    labs_info = sorted(labs_info, key=itemgetter(1), reverse=True)
    #print(labs_info)
    total_allocated = 0

    # To remove the labs from the dict
    for each_lab in labs_info:
        total_allocated += (int(each_lab[1]) + 2)
        if total_allocated > total_slots_given:
            print("\n=====ERROR: Number of hosts greater than number of slot=====")
            print("Lab", each_lab[0], "cannot be added")
            print("============================================================\n\n")
            l=[]
            for key, value in mac_map.items():
                if value == str(each_lab[0]):
                    l.append(mac_map[key])
                    #del mac_map[key]
            ln=[]
            for i in l:
                if i in ln:
                    continue
                else:
                    ln.append(i)
            for i in ln:
                if(i in mac_map.keys()):
                    del mac_map[i]
            deleted_labs.append(str(each_lab[0]))

    # *** DO WE ACCOMODATE MORE LABS? I THINK WHAT SUSOBHAN TOLD WAS WORNG! ***
    """
    To implement DNS as well, just subtract 1 from total_given_slots, and use the first addr
    as the DNS ans gateway. Just increment network addr and send to VLSM so that allocation happens
    from there.
    """

    # To remove the labs from labs_info at the end which cannot be accomodated
    stop_var = len(labs_info)
    i = 0
    while i < stop_var:
        if labs_info[i][0] in deleted_labs:
            print(labs_info[i])
            del labs_info[i]
            stop_var -= 1
            i -= 1
        i += 1

    print("DEPT INFO ")
    print("=========")
    for i in labs_info:
        if(i[0]!="REMAINING"):
            print("SUBNET NAME:",i[0],"Total Hosts Allocated:",i[1])
    print("=========\n")

    return labs_info


def VLSM(network_addr, labs_info):

    """
    Variable length subnet masking method with args -
    labs_info is the list of the tuple of lab_name and number of hosts it can hold.
    network_addr is the address where we start off with.
    """

    need = 0
    allc = 0
    bits = 0
    ipaddr = network_addr

    # Iterate over the labs' capacities
    for x in labs_info:
            bits = min_pow2(int(x[1]) + 2)
            ipaddr = get_network_address(ipaddr, convert_mask_to_ip(int(32 - bits)))

        # Get the first and last IPs
            first_addr = copy.deepcopy(ipaddr)  # list is mutable, not to change the global value
            first_addr[3] = int(int(first_addr[3]) + 1)

            last_addr = get_broadcast_address(ipaddr, convert_mask_to_ip(int(32 - bits)))
            last_addr[3] -= 1

        # Do the join of the first and last addresses here itself
            first_upd_addr = join (first_addr)
            last_upd_addr = join (last_addr)
            allocation.update({str(x[0]): [first_upd_addr, last_upd_addr, first_upd_addr, 32 - bits, first_upd_addr]})
            if(x[0]!="REMAINING"):
                print("DEPT SUBNET MASKS ")
                print("===========")
                print(" SUBNET: %5s NEEDED: %3d (%3d %% of) ALLOCATED %4d ADDRESS: %15s :: %15s - %-15s :: %15s MASK: %d (%15s)" % \
              (x[0],
               int(x[1]),
               (int(x[1]) * 100) / (int(pow(2, bits)) - 2),
               int(pow(2, bits)) - 2,
               join(ipaddr),
               join(first_addr),
               join(last_addr),
               join(get_broadcast_address(ipaddr, convert_mask_to_ip(int(32 - bits)))),
               32 - bits,
               join(convert_mask_to_ip(int(32 - bits)))))
                print ("===========\n")

            need += int(x[1])
            allc += int(pow(2, bits)) - 2
            ipaddr = get_next_usable_addr(ipaddr, convert_mask_to_ip(int(32 - bits)))


def run_server():
    avail_ip_addrs()
    """
    Main DHCP server which allocates IPs to the hosts
    """
    #dhcp_server = socket.socket()
    #dhcp_server.bind((HOST, PORT))
    #dhcp_server.listen(5)
    addr = ('', PORT) 
    
    dhcp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #host = ""
    dhcp_server.bind(addr)
    dhcp_server.settimeout(1000)


  

    print("Waiting For Client Request..")
    while True:
        #conn, addr = dhcp_server.accept()
        #print 'Got connection from', addr
        #data = conn.recv(1024)
        #print data

        try:
            
            data,address = dhcp_server.recvfrom(1024)
            print("DHCP Discover Request Received")
            print("Sent DHCP offer.")
            data = offer_get()
            dhcp_server.sendto(data, address)
            while 1:
                    try:
                        print("Waiting for  DHCP request.")
                        data, address = dhcp_server.recvfrom(1024)
                        print("Received DHCP request.")
                        #print(data)

                        print("Sent DHCP ACK.\n")
                        data = avl_ip_dr[0]
                        avl_ip_dr.remove(avl_ip_dr[0])
                        dt=bytearray()
                        dt.extend(data.encode())
                        dhcp_server.sendto(dt, address)
                        break
                    except:
                        raise
        except socket.timeout:
            print("Write timeout on server")

        #conn.send(new_client_ip)

        #conn.close()
        
    
    dhcp_server.close()

def main():

    # Check if file exists and open it
    try:
        subnet_file = open('subnets.conf', 'r')
    except OSError as err:
        print("OS Error: {0}".format(err))
        sys.exit(1)

    file_content = subnet_file.readlines()
    file_content = [x.strip() for x in file_content]

    # Validate the CIDR formatted: [IPv4]/[SubnetMask]
    validate_CIDR(file_content[0])

    # Store the validated CIDR in a variable for future use.
    CIDR = file_content[0]

    # Split the subnet CIDR_format_string
    CIDR_format_string = CIDR.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]

    labs_info = get_labs_info(file_content, subnet_mask)
    
    """
    VLSM SUBNET MASKING AND ASSIGNING IP ADDRESSES
    """
    print("VLSM AND ASSIGNING IP ADDRESS ")
    # We have to convert subnet masks to an equivalent IP format for processing. 
    subnet_list = convert_mask_to_ip(int(subnet_mask))

    # Split ip into list
    ip_addr = ip.split(".")
    for x in range(len(ip_addr)):
        ip_addr[x] = int(ip_addr[x])

    # Send this ip to get the N.A.
    network_addr = get_network_address(ip_addr, subnet_list)

    # HOW TO GIVE THE STARTING ADDR TO DNS?

    # Run the variable length subnet masking function
    VLSM(network_addr, labs_info)
    print("ALLOCATION")
    for i in allocation.keys():
        if(i!="REMAINING"):
            print("Department Name:",i," Network Address:",allocation[i][0]," Last Address:",allocation[i][1],"Starting Address:",allocation[i][2])
        else:
            print("REMAINING :"," Network Address:",allocation[i][0]," Last Address:",allocation[i][1],"Starting Address:",allocation[i][2])
    """
    Run the main DHCP server
    """
    run_server()


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())