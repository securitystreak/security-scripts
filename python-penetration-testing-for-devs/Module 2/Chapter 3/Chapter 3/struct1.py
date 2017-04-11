import socket
import struct

host = "192.168.0.1"
port = 12347

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
conn, addr = s.accept()
print "connected by", addr

msz= struct.pack('hhl', 1, 2, 3)

conn.send(msz)
conn.close()