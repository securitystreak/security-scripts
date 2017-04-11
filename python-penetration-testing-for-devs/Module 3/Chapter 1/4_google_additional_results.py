import urllib2
import json

GOOGLE_API_KEY = "{Insert your Google API key}"
target = "packtpub.com"
token = ""
loops = 0

while loops < 10:
	api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people?query="+target+"&key="+GOOGLE_API_KEY+"&maxResults=50&pageToken="+token).read()

	json_response = json.loads(api_response)
	token = json_response['nextPageToken']

	if len(json_response['items']) == 0:
		break

	for result in json_response['items']:
    		name = result['displayName']
	    	print name
	    	image = result['image']['url'].split('?')[0]
		f = open(name+'.jpg','wb+')
		f.write(urllib2.urlopen(image).read())
	loops+=1
