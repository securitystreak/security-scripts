import re

output = """Scanning mrrobot (10.0.0.100) [1000 ports] Discovered open port 1723/tcp on 10.0.0.100 
    Discovered open port 23/tcp on 10.0.0.100 Discovered open port 53/tcp on 10.0.0.100 Discovered 
    open port 80/tcp on 10.0.0.100Completed SYN Stealth Scan at 15:54, 0.14s elapsed (1000 total ports)"""

ports = set(re.findall('\d*/tcp',output))
print(ports)


