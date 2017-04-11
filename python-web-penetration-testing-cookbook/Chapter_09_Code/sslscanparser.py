import subprocess
import sys	

ipfile = sys.argv[1]

IPs = open(ipfile, "r")
output = open("sslscan.csv", "w+")

for IP in IPs:
	try:
		command = "sslscan "+IP

		ciphers = subprocess.check_output(command.split())

		for line in ciphers.splitlines():
			if "Accepted" in line:
				output.write(IP+","+line.split()[1]+","+line.split()[4]+","+line.split()[2]+"\r")
	except:
		pass