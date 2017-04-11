import socket
import struct
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
while True:

	pkt  = s.recvfrom(2048)
	banner = pkt[0][54:533]
	print banner
	print "--"*40
	
