#!/usr/bin/env python

import gzip
import os
from os.path import join
import re
import sys


# used to map session IDs to users and source IPs
session2user_ip = {}

def _logopen(filename):
    """Helper to provide transparent decompressing of compressed logs,
       if indicated by the file name.
    """
    if re.match(r'.*\.gz', filename):
        return gzip.open(filename, 'r')

    return open(filename, 'r')

def collect_session_data(vpxlogdir):
    """Uses vpx performance logs to map the session ID to
       source user name and IP"""
    extract = re.compile(r'SessionStats/SessionPool/Session/Id=\'([^\']+)\'/Username=\'([^\']+)\'/ClientIP=\'([^\']+)\'')

    logfiles = os.listdir(vpxlogdir)
    logfiles = filter(lambda x: 'vpxd-profiler-' in x, logfiles)
    for fname in logfiles:
        fpath = join(vpxlogdir, fname)
        f = _logopen(fpath)
            
        for line in f:
            m = extract.search(line)
            if m:
                session2user_ip[m.group(1)] = (m.group(2), m.group(3))

        f.close()

def print_cloning_hints(basedir):
    """Print timestamp, user, and IP address for VM cloning without
       by reconstructing from vpxd logs instead of accessing 
       the 'official' event logs"""
    vpxlogdir = join(basedir, 'ProgramData', 
                              'vCenterServer', 
                              'logs',
                              'vmware-vpx')
    collect_session_data(vpxlogdir)

    extract = re.compile(r'^([^ ]+).*BEGIN task-.*?vim\.VirtualMachine\.clone -- ([0-9a-f-]+).*')

    logfiles = os.listdir(vpxlogdir)
    logfiles = filter(lambda x: re.match('vpxd-[0-9]+.log(.gz)?', x), logfiles)
    logfiles.sort()

    for fname in logfiles:
        fpath = join(vpxlogdir, fname)
        f = _logopen(fpath)
            
        for line in f:
            m = extract.match(line)
            if m == None:
                continue
       
            timestamp = m.group(1)
            session = m.group(2)
            (user, ip) = session2user_ip.get(session, ('***UNKNOWN***', '***UNKNOWN***'))
            print 'Hint for cloning at %s by %s from %s' % (timestamp, user, ip)
            
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: %s vCenterLogDirectory' % sys.argv[0]
        sys.exit(1)

    print_cloning_hints(sys.argv[1])
