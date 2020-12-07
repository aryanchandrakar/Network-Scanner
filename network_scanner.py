#!/usr/bin/env python
import scapy.all as scapy

# making list of client and each client have dictionary with key value as ip, mac and their values
def scan(ip):
    # dicovering client thru mac request who has which mac
    # scapy.arping(ip)
    arp_request=scapy.ARP(pdst=ip)
    # the mac of the address we arp request ff:ff:ff....
    broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast= broadcast/arp_request
    # to get the field that can be edited
    answerlist=scapy.srp(arp_request_broadcast, timeout=30, verbose=False)[0]
    print("IP\t\t\tMAC address\n-----------------------------------------------")
    client_list=[]
    for e in answerlist:
        client_dict={"IP":e[1].psrc,"MAC":e[1].hwsrc}
        print(client_dict)
        client_list.append(client_dict)
        # hwsrc is the mac of the client and psrc is the ip of the client who replied
    return client_list

def result(result_list):
    for c in result_list:
        print(c["IP"]+"\t\t"+c["MAC"])

scan_result=scan("192.168.1.85")
# result(scan_result)