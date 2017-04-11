This is code that I am writing by following the *"Violent Python: A Cookbook for Hackers, Forensic Analysts, Penetration Testers and Security Engineers"* book. The code is not an exact copy because most of the code in the book is very un-pythonic, but they perform roughly the same tasks.

**Using some of these tools on machines that you do not own or have authorization to interact with is illegal and could land you in jail.**

Use something like virtualbox to setup a windows or linux box to run these on, avoiding any possible problems.

Setup
-----

Install the required packages:

    pip install -r requirements.txt

Included Programs
-----------------

Individual usage can be found by typing "./program_name.py --help"

###fping.py

Python replacement for the command line too l because it is broken on osx. Takes an ip list or a subnet and a list of ports and pings each host to see if it is alive.

###ftp.py

Scan hosts for anonymous logins or brute force the password for a user.

###metaspliot_smb.py

Script to attack hosts running smb with either a brute force attack or the conflicker attack

###nmap_scan.py

Scan the ports on the provided hosts

###ssh_botnet.py

Simple script to control multiple ssh hosts at once provided you have the user names and passwords, which you can get from:

###ssh\_brute\_forcer.py

Brute forces a host's ssh server with a provided worldlist

###url_checker.py

Find hidden paths on a http sever based upon a word list and a search pattern

Cool Examples
-------------

Find if a site has a hidden admin panel

    ./url_checker.py not_a_real_site.com/\{\} wordlist/general/admin-panels.txt

Check if two machines are alive

    ./fping.py list 10.0.1.1 10.0.1.2

Find all of the alive machines on your network

    ./fping.py subnet 10.0.1.0/24

Find all of the machines on your network and see if they have ssh open

    ./fping.py subnet 10.0.1.0/24 | ./nmap_scan.py 22

Find all the machines on the network, see if they have smb on them, and try to use the conflicker attack:

    ./fping.py subnet 10.0.1.0/24 | ./metasploit_smb.py 127.0.0.1 1337

License
-------

All code here is under the MIT license.
