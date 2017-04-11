#!/usr/bin/env python

'''
Author: Christopher Duffy
Date: February 2, 2015
Purpose: To grab your current Public IP (Eth & WLAN), Private IP, MAC Addresses, FQDN, and Hostname
Name: hostDetails.py

Copyright (c) 2015, Christopher Duffy All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met: * Redistributions 
of source code must retain the above copyright notice, this list of conditions and 
the following disclaimer. * Redistributions in binary form must reproduce the above 
copyright notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution. * Neither the 
name of the nor the names of its contributors may be used to endorse or promote 
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import os
import socket
import subprocess
import shutil
import errno
if os.name != "nt":
    import fcntl
import urllib2
import struct
import uuid

def get_ip(inter):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', inter[:15]))[20:24])
    return ip_addr

def get_mac_address(inter):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', inter[:15]))
    mac_address = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac_address

def get_localhost_details(interfaces_eth, interfaces_wlan):
    hostdata = "None"
    hostname = "None"
    windows_ip = "None"
    eth_ip = "None"
    wlan_ip = "None"
    host_fqdn = "None"
    eth_mac = "None"
    wlan_mac = "None"
    windows_mac = "None"
    hostname = socket.gethostbyname(socket.gethostname())
    if hostname.startswith("127.") and os.name != "nt":
        hostdata = socket.gethostbyaddr(socket.gethostname())
        hostname = str(hostdata[1]).strip('[]')
        host_fqdn = socket.getfqdn()
        for interface in interfaces_eth:
            try:
                eth_ip = get_ip(interface)
                if not "None" in eth_ip:
                    eth_mac = get_mac_address(interface)
                break
            except IOError:
                pass
        for interface in interfaces_wlan:
            try:
                wlan_ip = get_ip(interface)
                if not "None" in wlan_ip:
                    wlan_mac = get_mac_address(interface)
                break
            except IOError:
                pass
    else:
        windows_ip = socket.gethostbyname(socket.gethostname())
        windows_mac = uuid.getnode()
        windows_mac = ':'.join(("%012X" % windows_mac)[i:i+2] for i in range(0, 12, 2))
        hostdata = socket.gethostbyaddr(socket.gethostname())
        hostname = str(socket.gethostname())
        host_fqdn = socket.getfqdn()
    return hostdata, hostname, windows_ip, eth_ip, wlan_ip, host_fqdn, eth_mac, wlan_mac, windows_mac

def get_public_ip(request_target):
    grabber = urllib2.build_opener()
    grabber.addheaders = [('User-agent','Mozilla/5.0')]
    try:
        public_ip_address = grabber.open(target_url).read()
    except urllib2.HTTPError, error:
        print("There was an error trying to get your Public IP: %s") % (error)
    except urllib2.URLError, error:
        print("There was an error trying to get your Public IP: %s") % (error)
    return public_ip_address

wireless_ip = "None"
windows_ip = "None"
ethernet_ip = "None"
public_ip = "None"
host_fqdn = "None"
hostname = "None"
fqdn = "None"
ethernet_mac = "None"
wireless_mac = "None"
windows_mac = "None"
target_url = "http://ip.42.pl/raw"
inter_eth = ["eth0", "eth1", "eth2", "eth3"]
inter_wlan = ["wlan0", "wlan1", "wlan2", "wlan3", "wifi0", "wifi1", "wifi2", "wifi3", "ath0", "ath1", "ath2", "ath3"]


public_ip = get_public_ip(target_url)
hostdata, hostname, windows_ip, ethernet_ip, wireless_ip, host_fqdn, ethernet_mac, wireless_mac, windows_mac = get_localhost_details(inter_eth, inter_wlan)

if not "None" in public_ip:
    print("Your Public IP address is: %s") % (str(public_ip))
else:
    print("Your Public IP address was not found")

if not "None" in ethernet_ip:
    print("Your Ethernet IP address is: %s") % (str(ethernet_ip))
    print("Your Ethernet MAC address is: %s") % (str(ethernet_mac))
elif os.name != "nt":
    print("No active Ethernet Device was found")

if not "None" in wireless_ip:
    print("Your Wireless IP address is: %s") % (str(wireless_ip))
    print("Your Wireless Devices MAC Address is: %s") % (str(wireless_mac))
elif os.name != "nt":
    print("No active Wireless Device was found")

if not "None" in windows_ip:
    print("Your Windows Host IP address is: %s") % (str(windows_ip))
    print("Your Windows Mac address is: %s") % (str(windows_mac))
else:
    print("You are not running Windows")

if not "None" in hostname:
    print("Your System's hostname is: %s") % (hostname)

if host_fqdn == 'localhost':
    print("Your System is not Registered to a Domain")
else:
    print("Your System's Fully Qualifed Domain Name is: %s") % (host_fqdn)

 
