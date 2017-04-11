import threading
import time
import socket, subprocess,sys
from datetime import datetime
import thread
import shelve
'''section 1 '''
subprocess.call('clear',shell=True)
shelf = shelve.open("mohit.raj")
data=(shelf['desc'])
#shelf.sync()
'''section 2 '''
class myThread (threading.Thread):
    def __init__(self, threadName,rmip,r1,r2,c):
        threading.Thread.__init__(self)
        self.threadName = threadName
        self.rmip = rmip
        self.r1 = r1
        self.r2 = r2
        self.c =c
    def run(self):
            scantcp(self.threadName,self.rmip,self.r1,self.r2,self.c)
       
'''section 3 '''
def scantcp(threadName,rmip,r1,r2,c):
    try:
        for port in range(r1,r2):
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            #sock= socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            socket.setdefaulttimeout(c)
            result = sock.connect_ex((rmip,port))
            
            if result==0:
                print "Port Open:---->\t", port,"--", data.get(port, "Not in Database")
            sock.close()

    except KeyboardInterrupt:
         print "You stop this "
         sys.exit()

    except socket.gaierror:
         print "Hostname could not be resolved"
         sys.exit()

    except socket.error:
         print "could not connect to server"
         sys.exit()

    shelf.close()
'''section 4 '''
print "*"*60
print " \tWelcome this is the Port scanner of Mohit\n  "

d=raw_input("\t Press D for Domain Name or Press I for IP Address\t")   

if (d=='D' or d=='d'):
    rmserver = raw_input("\t Enter the Domain Name to scan:\t")
    rmip = socket.gethostbyname(rmserver)
elif(d=='I' or d=='i'):
    rmip = raw_input("\t Enter the IP Address  to scan:  ")

else: 
    print "Wrong input"
#rmip = socket.gethostbyname(rmserver)
r11 = int(raw_input("\t Enter the start port number\t"))
r21 = int (raw_input("\t Enter the last port number\t"))

conect=raw_input("For low connectivity press L and High connectivity Press H\t")

if (conect=='L' or conect=='l'):
    c =1.5

elif(conect =='H' or conect=='h'):
    c=0.5

else:
    print "\t wrong Input"

print "\n Mohit's Scanner is working on ",rmip
print "*"*60
t1= datetime.now()
tp=r21-r11

tn =30
                   # tn number of port handled by one thread
tnum=tp/tn                # tnum number of threads
if (tp%tn != 0):
    tnum= tnum+1

if (tnum > 300):
    tn = tp/300
    tn= tn+1
    tnum=tp/tn
    if (tp%tn != 0):
        tnum= tnum+1

'''section  5'''
threads= []

try:
    for i in range(tnum):
        #print "i is ",i
        k=i
        r2=r11+tn 
       # thread=str(i)
        thread = myThread("T1",rmip,r11,r2,c)
        thread.start()
	threads.append(thread)
        r11=r2

except:
     print "Error: unable to start thread"

print "\t Number of Threads active:", threading.activeCount()

for t in threads:
    t.join()
print "Exiting Main Thread"
t2= datetime.now()

total =t2-t1
print "scanning complete in " , total

print "\n*****Thanks for using Mohit's Port Scanner****"
print "You can update database file"
print "use command python > python updata.py"
print "Give feedback to mohitraj.cs@gmail.com"



