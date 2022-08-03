from scapy.all import *
import time
import os
from playsound import playsound


def listen_dhcp():
    sniff(prn=print_packet, filter='udp and (port 67 or port 68)')

def print_packet(packet):
    target_mac, requested_ip, hostname, vendor_id = [None] * 4
    if packet.haslayer(Ether):
        target_mac = packet.getlayer(Ether).src
    dhcp_options = packet[DHCP].options
    for item in dhcp_options:
        try:
            label, value = item
        except ValueError:
            continue
        if label == 'requested_addr':
            requested_ip = value
        elif label == 'hostname':
            hostname = value.decode()
        elif label == 'vendor_class_id':
            vendor_id = value.decode()
    if target_mac and vendor_id and hostname and requested_ip:
        time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
        print(f"{time_now} : {target_mac}  -  {hostname} / {vendor_id} requested {requested_ip}")

    if (hostname == 'hostname' or requested_ip == 'requested_ip' or vendor_id == 'vendor_id'): #<---- Change this 
      for i in range(10):
        print("TARGET CONNECTED")
      playsound('ubell.wav')
      
if __name__ == "__main__":
    listen_dhcp()
    print("Nasluchuje")
