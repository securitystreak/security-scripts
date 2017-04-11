import urllib
from bs4 import BeautifulSoup
url = raw_input("Enter the URL ")
ht= urllib.urlopen(url)
html_page = ht.read()
b_object = BeautifulSoup(html_page)
print b_object.title
print b_object.title.text
for link in b_object.find_all('a'):
	print(link.get('href'))

