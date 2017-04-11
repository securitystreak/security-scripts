from scapy.all import *
interface = 'mon0'
ap_list = []
def info(fm):
	if fm.haslayer(Dot11):
		
		if ((fm.type == 0) & (fm.subtype==8)):
			if fm.addr2 not in ap_list:
				ap_list.append(fm.addr2)
				print "SSID--> ",fm.info,"-- BSSID --> ",fm.addr2
				
sniff(iface=interface,prn=info)
