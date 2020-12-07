#!/usr/bin/env python
import scapy.all as scapy
import optparse #older version
import argparse #newer version just change optparse to argparse

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
        client_list.append(client_dict)
        # hwsrc is the mac of the client and psrc is the ip of the client who replied
    return client_list

def result(result_list):
    print("IP\t\t\tMAC")
    for c in result_list:
        print(c["IP"]+"\t\t"+c["MAC"])

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="ip range wanted")
    (options, arguments) = parser.parse_args()
    if not options.target:
        # if options.interface does not hold the value
        parser.error("[-] Please specify an ip, use --help for more info.")
    return options

options=get_arguments()
scan_result=scan(options.target)
result(scan_result)