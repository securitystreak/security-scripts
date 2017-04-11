import shelve
def create():
	shelf = shelve.open("mohit.raj", writeback=True)
	shelf['desc'] ={}
	shelf.close()
	print "Dictionary is created"


def update():
    shelf = shelve.open("mohit.raj", writeback=True)
    data=(shelf['desc'])
    port =int(raw_input("Enter the Port: "))
    data[port]= raw_input("\n Enter the  description\t")
    shelf.close()
    
def del1():
    shelf = shelve.open("mohit.raj", writeback=True)
    data=(shelf['desc'])
    port =int(raw_input("Enter the Port: "))
    del data[port]
    shelf.close()
    print "\nEntry is deleted"
    

def list1():
    print "*"*30
    shelf = shelve.open("mohit.raj", writeback=True)
    data=(shelf['desc'])
    for key, value in data.items():
        print key, ":", value
    print "*"*30
print "\t Program to update or Add and Delete the port number detail\n"
while(True):
	print "Press" 
	print "C for create only one time create"
	print "U for Update or Add \nD for delete"
	print "L for list the all values  "
	print "E for Exit  "
	c=raw_input("Enter :  ")  

	if (c=='C' or c=='c'):
		create()

	elif (c=='U' or c=='u'):
		update()

	elif(c=='D' or c=='d'):
		del1()

	elif(c=='L' or c=='l'):
		list1()
		
	elif(c=='E' or c=='e'):
		exit()

	else:
		print "\t Wrong Input"




