'''
Copyright (c) 2016 Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Script Purpose: Python Template for MPE+ Integration
Script Version: 1.0
Script Author:  C.Hosmer

Script Revision History:
Version 1.0 April 2016 

'''
# Script Module Importing

# Python Standard Library Modules
import os               # Operating/Filesystem Module
from sys import argv    # The systems argument vector, in Python this is
                        # a list of elements from the command line

# Script Constants

'''
Python does not support constants directly
however, by initializing variables here and
specifying them as UPPER_CASE you can make your
intent known
'''
# General Constants
SCRIPT_NAME    = "Script: MPE+ Command Line Arguments"
SCRIPT_VERSION = "Version 1.0"
SCRIPT_AUTHOR  = "Author: C. Hosmer, Python Forensics"
SCRIPT_RELEASE = "April 2016"

# Print out some basics

print(SCRIPT_NAME)
print(SCRIPT_AUTHOR)
print(SCRIPT_VERSION, SCRIPT_RELEASE)

# Obtain the command line arguments using
# the system argument vector

# For MPE+ Scripts the length of the argument vector is
# always 2  scriptName, path  

if len(argv) == 2:
    scriptName, path = argv
else:
    print(argv, "Invalid Command line")
    quit()

print("Command Line Argument Vector")
print("Script Name: ", scriptName)
print("Script Path: ", path)

# Verify the path exists and determine
# the path type

if os.path.exists(path):
    print("Path Exists")
    if os.path.isdir(path):
        print("Path is a directory")
    elif os.path.isfile(path):
        print("Path is a file")
    else:
        print(path, "is invalid")
else:
    print(path, "Does not exist")

print ("Script Complete")