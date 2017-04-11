#!/usr/bin/python
#
# Copyright (C) 2015 Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys, subprocess, hashlib


def get_apps():
    
    # dumping the list of installed apps from the device
    print "Dumping apps meta data ..."
    
    meta = subprocess.Popen(['adb', 'shell', 'ls', '-l', '/data/app'], 
        stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    meta.wait()

    apps = []
    while True:
        line = meta.stdout.readline()
        if line != '':
            name = line.split(' ')[-1].rstrip()
            date = line.split(' ')[-3]
            time = line.split(' ')[-2]
            if name.split('.')[-1] == 'apk':
                app = [name, date, time]
            else:
                continue
        else:
            break
        apps.append(app)

    return apps


def dump_apps(apps, backup_dir):

    # dumping the apps from the device
    print "Dumping the apps ..."

    for app in apps:
        app = app[0]
        subprocess.Popen(['adb', 'pull', '/data/app/' + app, backup_dir], 
            stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)


def get_hashes(apps, backup_dir):

    # calculating the hashes
    print "Calculating the sha256 hashes ..."

    meta = []
    for app in apps:
        try:
            sha256 = hashlib.sha256(open(backup_dir + '/' + app[0], 'rb').read()).hexdigest()
            md5 = hashlib.md5(open(backup_dir + '/' + app[0], 'rb').read()).hexdigest()
            app.append(sha256)
            app.append(md5)
            meta.append(app)
        except:
            continue

    return meta


if __name__ == '__main__':

    # check if device is connected and adb is running as root
    if subprocess.Popen(['adb', 'get-state'], stdout=subprocess.PIPE).communicate(0)[0].split("\n")[0] == "unknown":
        print "no device connected - exiting..."
        sys.exit(2)

    # starting to create the output directory
    backup_dir = sys.argv[1]

    try:
        os.stat(backup_dir)
    except:
        os.mkdir(backup_dir)

    apps = get_apps()
    dump_apps(apps, backup_dir)
    meta = get_hashes(apps, backup_dir)

    # printing the list of installed apps
    for app in meta:
        print "\033[0;32m" + ' '.join(app) + "\033[m"