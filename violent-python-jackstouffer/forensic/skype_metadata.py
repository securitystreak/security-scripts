#!./env/bin/python

""" Skype Sqlite Database Extractor

    Takes the sqlite skype database and parses the data. On windows
    the path is C:\\Documents and Settings\\"User"\\Application Data\\Skype\\"Skype-account"\\main.db
    On OSX the path is /Users/"User"/Library/Application\ Support/Skype/"Skype account"/main.db

    Don't be a moron, please don't use this for something illegal.

    Usage:
        exif_metadata.py users <sqlite>
        exif_metadata.py contacts <sqlite>
        exif_metadata.py calls <sqlite>
        exif_metadata.py messages <sqlite>
        exif_metadata.py -h | --help
        exif_metadata.py --version

    Options:
        -h, --help      Display this message
        --version       Display the version of this program

    Example:
        skype_metadata.py messages ~/Library/Application\ Support/Skype/some_account/main.db
"""

import sqlite3
from docopt import docopt
from colorama import init, Fore


def users(skypeDB):
    conn = sqlite3.connect(skypeDB)
    c = conn.cursor()
    c.execute("SELECT fullname, skypename, city, country,"
              "datetime(profile_timestamp,'unixepoch') FROM Accounts;")
    for row in c:
        print Fore.GREEN + 'Found Account' + Fore.RESET

        print '[+] User : ' + str(row[0])
        print '[+] Skype Username : ' + str(row[1])
        print '[+] Location : ' + str(row[2]) + ',' + str(row[3])
        print '[+] Profile Date : ' + str(row[4])


def contacts(skypeDB):
    conn = sqlite3.connect(skypeDB)
    c = conn.cursor()
    c.execute("SELECT displayname, skypename, city, country,\
    phone_mobile, birthday FROM Contacts;")
    for row in c:
        print Fore.GREEN + 'Found Contact' + Fore.RESET

        print '[+] User : ' + str(row[0])
        print '[+] Skype Username : ' + str(row[1])

        if str(row[2]) != '' and str(row[2]) != 'None':
            print '[+] Location : ' + str(row[2]) + ',' + str(row[3])
        if str(row[4]) != 'None':
            print '[+] Mobile Number: ' + str(row[4])
        if str(row[5]) != 'None':
            print '[+] Birthday: ' + str(row[5])


def calls(skypeDB):
    conn = sqlite3.connect(skypeDB)
    c = conn.cursor()
    c.execute("SELECT datetime(begin_timestamp,'unixepoch'),"
              "identity FROM calls, conversations WHERE calls.conv_dbid = conversations.id;")

    print Fore.GREEN + 'Found Calls' + Fore.RESET

    for row in c:
        print '[+] Time: ' + str(row[0]) + ' | Partner: ' + str(row[1])


def messages(skypeDB):
    conn = sqlite3.connect(skypeDB)
    c = conn.cursor()
    c.execute("SELECT datetime(timestamp,'unixepoch'), "
              "dialog_partner, author, body_xml FROM Messages;")

    print Fore.GREEN + 'Found Messages' + Fore.RESET

    for row in c:
        try:
            if 'partlist' not in str(row[3]):
                if str(row[1]) != str(row[2]):
                    msgDirection = 'To ' + str(row[1]) + ': '
                else:
                    msgDirection = 'From ' + str(row[2]) + ': '
                    print 'Time: ' + str(row[0]) + ' ' + msgDirection + str(row[3])
        except:
            pass


def main():
    arguments = docopt(__doc__, version=0.1)
    init()
    skypeDB = arguments['<sqlite>']

    if arguments['users']:
        users(skypeDB)
    elif arguments['contacts']:
        contacts(skypeDB)
    elif arguments['calls']:
        calls(skypeDB)
    elif arguments['messages']:
        messages(skypeDB)

if __name__ == '__main__':
    main()
