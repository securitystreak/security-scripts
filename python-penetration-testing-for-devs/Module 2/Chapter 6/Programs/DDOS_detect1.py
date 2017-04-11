import socket
import struct
from datetime import datetime
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
dict = {}
file_txt = open("dos.txt",'a')
file_txt.writelines("**********")
t1= str(datetime.now())
file_txt.writelines(t1)
file_txt.writelines("**********")
file_txt.writelines("\n")
print "Detection Start ......."
D_val =10
D_val1 = D_val+10
while True:

	pkt  = s.recvfrom(2048)
	ipheader = pkt[0][14:34]
	ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
	IP = socket.inet_ntoa(ip_hdr[3])
	print "Source IP", IP
	if dict.has_key(IP):
		dict[IP]=dict[IP]+1
		print dict[IP]
		if(dict[IP]>D_val) and (dict[IP]<D_val1) :
			
				line = "DDOS Detected "
				file_txt.writelines(line)
				file_txt.writelines(IP)
				file_txt.writelines("\n")
				
	else:
		dict[IP]=1
	

	
	


