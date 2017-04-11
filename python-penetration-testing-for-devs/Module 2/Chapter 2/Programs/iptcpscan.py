import socket 
from datetime import datetime
net= raw_input("Enter the IP address ")
net1= net.split('.')
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
st1 = int(raw_input("Enter the Starting Number "))
en1 = int(raw_input("Enter the Last Number "))
en1=en1+1
t1= datetime.now()
def scan(addr):
	sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(1)
	result = sock.connect_ex((addr,445))
	if result==0:
		return 1
	else :
		return 0
		
def run1():
	for ip in xrange(st1,en1):
		addr = net2+str(ip)
		if (scan(addr)):
			print addr , "is live"
			
run1()
t2= datetime.now()
total =t2-t1
print "scanning complete in " , total