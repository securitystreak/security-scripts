import socket 
host = "192.168.0.1" #Server address
port = 12345  #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server 
s.listen(2) 
conn, addr = s.accept()  
print addr, "Now Connected"
conn.send("Thank you for connecting")
conn.close()
