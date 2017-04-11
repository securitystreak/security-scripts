import shelve
def create():
	print "This only for One key "
	s = shelve.open("mohit.xss",writeback=True)
	s['xss']= []

def update():
	s = shelve.open("mohit.xss",writeback=True)
	val1 = int(raw_input("Enter the number of values  "))
		
	for x in range(val1):
		val = raw_input("\n Enter the value\t")
		(s['xss']).append(val)
	s.sync()
	s.close()

def retrieve():
	r = shelve.open("mohit.xss",writeback=True)
	for key in r:
		print "*"*20
		print key
		print r[key]
		print "Total Number ", len(r['xss'])
	r.close()

while (True):
	print "Press"
	print "  C for Create, \t  U for Update,\t  R for retrieve"
	print "  E for exit"
	print "*"*40
	c=raw_input("Enter \t")  
	if (c=='C' or c=='c'):
		create()

	elif(c=='U' or c=='u'):
		update()
	
	elif(c=='R' or c=='r'):
		retrieve()
	
	elif(c=='E' or c=='e'):
		exit()
	else:
		print "\t Wrong Input"