import sys

if len(sys.argv) !=3:
	print "usage: %s name.txt email suffix" % (sys.argv[0])
	sys.exit(0)
for line in open(sys.argv[1]):
	name = ''.join([c for c in line if c == " " or c.isalpha()])
	tokens = name.lower().split()
	fname = tokens[0]
	lname = tokens[-1]
	print fname +lname+sys.argv[2]
	print lname+fname+sys.argv[2]
	print fname+"."+lname+sys.argv[2]
	print lname+"."+fname+sys.argv[2]
	print lname+fname[0]+sys.argv[2]
	print fname+lname+fname+sys.argv[2]
	print fname[0]+lname+sys.argv[2]
	print fname[0]+"."+lname+sys.argv[2]
	print lname[0]+"."+fname+sys.argv[2]
	print fname+sys.argv[2]
	print lname+sys.argv[2]