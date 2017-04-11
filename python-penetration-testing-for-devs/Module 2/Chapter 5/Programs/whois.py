import urllib
from bs4 import BeautifulSoup
import re
domain=raw_input("Enter the domain name ")
url = "http://smartwhois.com/whois/"+str(domain)
ht= urllib.urlopen(url)
html_page = ht.read()
b_object = BeautifulSoup(html_page)
file_text= open("who.txt",'a')
who_is = b_object.body.find('div',attrs={'class' : 'whois'})
who_is1=str(who_is)

for match in re.finditer("Domain Name:",who_is1):
			s= match.start()
			

lines_raw = who_is1[s:]	
lines = lines_raw.split("<br/>",150)		
i=0
for line in lines :
	file_text.writelines(line)
	file_text.writelines("\n")
	print line
	i=i+1
	if i==17 :
		break
file_text.writelines("-"*50)
file_text.writelines("\n")
file_text.close()

		
	





