import urllib2
import json

GOOGLE_API_KEY = "{Insert your Google API key}"
target = "packtpub.com"
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people?query="+target+"&key="+GOOGLE_API_KEY).read()

json_response = json.loads(api_response)
for result in json_response['items']:
    	name = result['displayName']
    	print name
    	image = result['image']['url'].split('?')[0]
	f = open(name+'.jpg','wb+')
	f.write(urllib2.urlopen(image).read())
	f.close()
