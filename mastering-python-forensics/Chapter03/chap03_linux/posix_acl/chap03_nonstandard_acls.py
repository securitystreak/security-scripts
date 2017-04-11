#!/usr/bin/env python

import os
from os.path import join
import posix1e
import re
import stat
import sys

def acls_from_file(filename, include_standard = False):
    """Returns the extended ACL entries from the given
       file as list of the text representation.

       Arguments:
       filename -- the file name to get the ACLs from
       include_standard -- if True, ACL entries representing 
                           standard Linux permissions will be
                           included"""
    result = []
    try:
        acl = posix1e.ACL(file=filename)
    except:
        print 'Error getting ACLs from %s' % filename
        return []

    text = acl.to_any_text(options=posix1e.TEXT_ABBREVIATE | posix1e.TEXT_NUMERIC_IDS)

    for entry in text.split("\n"):
        if not include_standard and \
           re.search(r'^[ugo]::', entry) != None:
            continue
        result.append(entry)

    return result


def get_acl_list(basepath, include_standard = False):
    """Collects all POSIX ACL entries of a directory tree.

    Arguments:
    basepath -- directory to start from
    include_standard -- if True, ACL entries representing 
                        standard Linux permissions will be
                        included"""
    result = {}

    for root, dirs, files in os.walk(basepath):
        for f in dirs + files:
            fullname = join(root, f)

            # skip symbolic links (target ACL applies)
            if stat.S_ISLNK(os.lstat(fullname).st_mode):
                continue

            acls = acls_from_file(fullname, include_standard)
            if len(acls) > 0:
                result[fullname] = acls

    return result

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage %s root_directory' % sys.argv[0]
        sys.exit(1)

    acl_list = get_acl_list(sys.argv[1], False)

    for filename, acls in acl_list.iteritems():
        print "%s: %s" % (filename, ','.join(acls))
