#!./env/bin/python

""" iPhone Messages Extractor

    Takes an iPhone backup and extracts the imessages

    Don't be a moron, please don't use this for something illegal.

    Usage:
        iphone_backups.py <backup>
        iphone_backups.py -h | --help
        iphone_backups.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program
"""

import os
import sqlite3
from docopt import docopt
from colorama import init, Fore


def is_message_table(iphoneDB):
    try:
        conn = sqlite3.connect(iphoneDB)
        c = conn.cursor()
        c.execute('SELECT tbl_name FROM sqlite_master'
                  'WHERE type==\"table\";')
        for row in c:
            if 'message' in str(row):
                return True
    except:
        return False


def printMessage(msgDB):
    try:
        conn = sqlite3.connect(msgDB)
        c = conn.cursor()
        c.execute("select datetime(date,'unixepoch')"
                  "address, text from message WHERE address>0;")
        for row in c:
            date = str(row[0])
            addr = str(row[1])
            text = row[2]
        print 'Date: ' + date + ', Addr: ' + addr + ' Message: ' + text
    except:
        pass


def main():
    init()
    arguments = docopt(__doc__, version=0.1)
    dir_list = os.listdir(arguments['<backup>'])

    for file_name in dir_list:
        iphoneDB = os.path.join(arguments['<backup>'], file_name)
        if is_message_table(iphoneDB):
            try:
                print Fore.GREEN + 'Found Messages' + Fore.RESET
                printMessage(iphoneDB)
            except:
                pass

if __name__ == '__main__':
    main()
