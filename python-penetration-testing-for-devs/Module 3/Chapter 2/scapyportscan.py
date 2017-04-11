import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys 
from scapy.all import *

if len(sys.argv) !=4:
    print "usage: %s target startport endport" % (sys.argv[0])
    sys.exit(0)

target = str(sys.argv[1])
startport = int(sys.argv[2])
endport = int(sys.argv[3])
print "Scanning "+target+" for open TCP ports\n"
if startport==endport:
	endport+=1
for x in range(startport,endport):
    packet = IP(dst=target)/TCP(dport=x,flags="S")
    response = sr1(packet,timeout=0.5,verbose=0)   
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
		print "Port "+str(x)+" is open!"
		sr(IP(dst=target)/TCP(dport=response.sport,flags="R"),timeout=0.5, verbose=0)		

print "Scan complete!\n"