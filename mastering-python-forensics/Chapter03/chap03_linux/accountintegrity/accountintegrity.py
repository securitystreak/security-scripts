#!/usr/bin/python

import re
import sys

def read_passwd(filename):
    """Reads entries from shadow or passwd files and
       returns the content as list of entries.
       Every entry is a list of fields."""

    content = []
    with open(filename, 'r') as f:
        for line in f:
            entry = line.strip().split(':')
            content.append(entry)

    return content

def detect_aliases(passwd):
    """Prints users who share a user id on the console
    
       Arguments:
       passwd -- contents of /etc/passwd as read by read_passwd"""

    id2user = {}
    for entry in passwd:
        username = entry[0]
        uid = entry[2]
        if uid in id2user:
            print 'User "%s" is an alias for "%s" with uid=%s' % (username, id2user[uid], uid)
        else:
            id2user[uid] = username

def detect_missing_users(passwd, shadow):
    """Prints users of /etc/passwd missing in /etc/shadow
       and vice versa.

       Arguments:
       passwd -- contents of /etc/passwd as read by read_passwd
       shadow -- contents of /etc/shadow as read by read_passwd"""

    passwd_users = set([e[0] for e in passwd])
    shadow_users = set([e[0] for e in shadow])

    missing_in_passwd = shadow_users - passwd_users
    if len(missing_in_passwd) > 0:
        print 'Users missing in passwd: %s' % ', '.join(missing_in_passwd)

    missing_in_shadow = passwd_users - shadow_users
    if len(missing_in_shadow) > 0:
        print 'Users missing in shadow: %s' % ', '.join(missing_in_shadow)

def detect_unshadowed(passwd, shadow):
    """Prints users who are not using shadowing or have no password set
    
       Arguments:
       passwd -- contents of /etc/passwd as read by read_passwd"""

    nopass = [e[0] for e in passwd if e[1]=='']
    nopass.extend([e[0] for e in shadow if e[1]==''])
    if len(nopass) > 0:
        print 'Users without password: %s' % ', '.join(nopass)

    unshadowed = [e[0] for e in passwd if e[1] != 'x' and e[1] != '']
    if len(unshadowed) > 0:
        print 'Users not using password-shadowing: %s' % \
              ', '.join(unshadowed)


def detect_deviating_hashing(shadow):
    """Prints users with non-standard hash methods for passwords
    
       Arguments:
       shadow -- contents of /etc/shadow as read by read_passwd"""

    noalgo = set()
    salt2user = {}
    algorithms = set()
    for entry in shadow:
        pwhash = entry[1]
        if len(pwhash) < 3:
            continue
        
        m = re.search(r'^\$([^$]{1,2})\$([^$]+)\$', pwhash)
        if not m:
            noalgo.add(entry[0])
            continue
        
        algo = m.group(1)
        salt = m.group(2)
        
        if salt in salt2user:
            print 'Users "%s" and "%s" share same password salt "%s"' % \
                  (salt2user[salt], entry[0], salt)
        else:
            salt2user[salt] = entry[0]

        algorithms.add(algo)

    if len(algorithms) > 1:
        print 'Multiple hashing algorithms found: %s' % ', '.join(algorithms)

    if len(noalgo) > 0:
        print 'Users without hash algorithm spec. found: %s' % \
              ', '.join(noalgo)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage %s /path/to/passwd /path/to/shadow' % sys.argv[0]
        sys.exit(1)

    passwd = read_passwd(sys.argv[1])
    shadow = read_passwd(sys.argv[2])

    detect_aliases(passwd)
    detect_missing_users(passwd, shadow)
    detect_unshadowed(passwd, shadow)
    detect_deviating_hashing(shadow)
