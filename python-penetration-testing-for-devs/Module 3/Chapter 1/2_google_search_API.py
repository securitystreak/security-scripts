import urllib2

GOOGLE_API_KEY = "{Insert your Google API key}" 
target = "packtpub.com"
api_response = urllib2.urlopen("https://www.googleapis.com/plus/v1/people?query="+target+"&key="+GOOGLE_API_KEY).read()
api_response = api_response.split("\n")
for line in api_response:
    if "displayName" in line:
        print line