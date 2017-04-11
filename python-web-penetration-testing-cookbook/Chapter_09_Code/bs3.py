import urllib2
import re
import sys

tarurl = sys.argv[1]
url = urllib2.urlopen(tarurl).read()
regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))

print"<MaltegoMessage>"
print"<MaltegoTransformResponseMessage>"
print"	<Entities>"
emails = re.findall(regex, url)
for email in emails:
	print"		<Entity Type=\"maltego.EmailAddress\">"
	print"			<Value>"+str(email[0])+"</Value>"
	print"		</Entity>"
print"	</Entities>"
print"</MaltegoTransformResponseMessage>"
print"</MaltegoMessage>"