#! /usr/bin/env python

import sys
from scapy.all import srp,Ether,ARP,conf

if len(sys.argv) != 2:
        print "Usage: arp_ping <net> (e.g.,: arp_ping 192.168.1.0/24)"
        sys.exit(1)

conf.verb=0
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),
timeout=9)

print r"+------------------+-----------------+"
print r"|       MAC        |        IP       |"
print r"+------------------+-----------------+"
for snd,rcv in ans:
        print rcv.sprintf(r" %Ether.src% | %ARP.psrc%")
print r"+------------------+-----------------+" 
