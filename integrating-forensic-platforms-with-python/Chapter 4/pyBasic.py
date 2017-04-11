# Guidance Test Python Application
# pyBasic.py
#
# Author: C. Hosmer
# Python Fornesics, Inc.
#
# May 2015
# Version 1.0
#

'''
Copyright (c) 2015 Chet Hosmer, Python Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

'''

import argparse                 # Python Standard Library : Argument Parsing
import time                     # Python Standard Library : Time methods
import os                       # Python Standard Library : Operating System Methods

parser = argparse.ArgumentParser()
parser.add_argument('file')
args = parser.parse_args()

theFile = args.file

print "Test Python Application integrated with EnCase v7"

# get the file statistics
theFileStat =  os.stat(theFile)

# get the MAC Times and store them in a list

macTimes = []
macTimes.append(time.ctime(theFileStat.st_mtime))
macTimes.append(time.ctime(theFileStat.st_atime))
macTimes.append(time.ctime(theFileStat.st_ctime))

# get and store the File size

fileSize = theFileStat.st_size

print "Filename     : ", theFile
print "Filesize     : ", fileSize
print "Last Modified: ", macTimes[0]
print "Last Access  : ", macTimes[1]
print "Created      : ", macTimes[2]

    