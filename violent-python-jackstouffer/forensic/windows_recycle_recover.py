#!./env/bin/python

""" Windows Deleted Files Recovery

    Finds the location of deleted files and lists them and their
    owner.

    Don't be a moron, please don't use this for something illegal.

    Usage:
        windows_registry.py
        windows_registry.py -h | --help
        windows_registry.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program
"""

import os
from _winreg import OpenKey, QueryValueEx, HKEY_LOCAL_MACHINE
from docopt import docopt
from colorama import Fore, init


def find_recycled():
    """ The recycled items dir is different in different versions of windows
    """

    dirs = ['C:\\Recycler\\', 'C:\\Recycled\\', 'C:\\$Recycle.Bin\\']

    for recycleDir in dirs:
        if os.path.isdir(recycleDir):
            return recycleDir

    return None


def sid2user(sid):
    try:
        key = OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + '\\' + sid)
        (value, type) = QueryValueEx(key, 'ProfileImagePath')
        user = value.split('\\')[-1]
        return user
    except:
        return sid


def recycled_files(recycleDir):
    dirList = os.listdir(recycleDir)
    for sid in dirList:
        files = os.listdir(recycleDir + sid)
        user = sid2user(sid)
        print '[*] Listing Files For User: ' + str(user)
        for file in files:
            print Fore.GREEN + '[+] Found File: ' + str(file) + Fore.RESET


def main():
    recycledDir = find_recycled()
    recycled_files(recycledDir)

if __name__ == '__main__':
    init()
    docopt(__doc__, version=0.1)
    main()
