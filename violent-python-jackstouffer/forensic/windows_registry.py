#!./env/bin/python

""" Windows Registry Network Query

    Lists the network name and MAC addresses of the networks that
    this computer has connected to. If the location command is given
    print the coordinates of the network if they are in the wigile
    datebase

    Don't be a moron, please don't use this for something illegal.

    Usage:
        windows_registry.py
        windows_registry.py location <username> <password>
        windows_registry.py -h | --help
        windows_registry.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program
"""

import mechanize
import urllib
import re
from _winreg import OpenKey, EnumKey, EnumValue, HKEY_LOCAL_MACHINE, CloseKey
from docopt import docopt


def binary2mac(binary):
    address = ""

    for char in binary:
        address += ("%02x " % ord(char))

    address = address.strip(" ").replace(" ", ":")[0:17]
    return address


def wigle_print(username, password, netid):
    browser = mechanize.Browser()

    browser.open('http://wigle.net')
    reqData = urllib.urlencode({'credential_0': username,
                                'credential_1': password})

    browser.open('https://wigle.net//gps/gps/main/login', reqData)

    params = {}
    params['netid'] = netid
    reqParams = urllib.urlencode(params)
    respURL = 'http://wigle.net/gps/gps/main/confirmquery/'
    resp = browser.open(respURL, reqParams).read()

    mapLat = 'N/A'
    mapLon = 'N/A'
    rLat = re.findall(r'maplat=.*\&', resp)

    if rLat:
        mapLat = rLat[0].split('&')[0].split('=')[1]
        rLon = re.findall(r'maplon=.*\&', resp)

    if rLon:
        mapLon = rLon[0].split

    print '[-] Lat: ' + mapLat + ', Lon: ' + mapLon


def print_networks(username=None, password=None):
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE, net)

    print '\n[*] Networks You have Joined.'

    for i in range(100):
        try:
            guid = EnumKey(key, i)
            netKey = OpenKey(key, str(guid))
            (n, addr, t) = EnumValue(netKey, 5)
            (n, name, t) = EnumValue(netKey, 4)

            mac = binary2mac(addr)
            net_name = str(name)

            print '[+] ' + net_name + ' ' + mac
            wigle_print(username, password, mac)
            CloseKey(netKey)
        except:
            break


def main():
    arguments = docopt(__doc__, version=0.1)

    if arguments['location']:
        print_networks(username=arguments['username'], password=arguments['password'])
    else:
        print_networks()

if __name__ == '__main__':
    main()
