from ftplib import FTP
import time
import os

user = sys.argv[1]
pw = sys.argv[2]

ftp = FTP("127.0.0.1", user, pw)

filescheck = "aa"

loop = 0
up = "../"

while 1:
	files = os.listdir("./"+(i*up))
	print files

	for f in files:
		try:		
			fiile = open(f, 'rb')
			ftp.storbinary('STOR ftpfiles/00'+str(f), fiile)
			fiile.close()
		else:
			pass

	if filescheck == files:
		break
	else:
		filescheck = files
		loop = loop+1
		time.sleep(10)
ftp.close()
