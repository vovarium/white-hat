#!/usr/bin/env python

import scapy.all as scapy

packet = scapy.ARP(op=2, pdst="10.0.2.7", hwdst="08:00:27:8a:21:73", psrc="10.0.2.1")
