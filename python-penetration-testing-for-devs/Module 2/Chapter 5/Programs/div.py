import urllib
from bs4 import BeautifulSoup
url = "https://www.hackthissite.org"
ht= urllib.urlopen(url)
html_page = ht.read()
b_object = BeautifulSoup(html_page)
data = b_object.find('div', id ='notice')
print data