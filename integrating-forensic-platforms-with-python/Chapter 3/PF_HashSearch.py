
'''
Copyright (c) 2016 Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Script Purpose: Python HashSearch for MPE+
Script Version: 1.0
Script Author:  C.Hosmer

Script Revision History:
Version 1.0 April 2016 

'''
# Script Module Importing

# Python Standard Library Modules
import os               # Operating/Filesystem Module
import time             # Basic Time Module
import logging          # Script Logging
import hashlib          # Python Hashing Module
from sys import argv    # Command Line arguments

# Import 3rd Party Modules

# End of Script Module Importing


# Script Constants

'''
Python does not support constants directly
however, by initializing variables here and
specifying them as UPPER_CASE you can make your
intent known
'''
# General Constants
SCRIPT_NAME    = "Script: Hash Search for MPE+ "
SCRIPT_VERSION = "Version 1.0"
SCRIPT_AUTHOR  = "Author: C. Hosmer, Python Forensics"
SCRIPT_LOG     = "C:/SYN/HashSearch/FORENSIC_LOG.txt"
SRC_HASH       = "C:/SYN/HashSearch/Hashes.txt"
CSV            = "C:/SYN/HashSearch/results.csv"

# LOG Constants used as input to LogEvent Function
LOG_DEBUG = 0           # Debugging Event
LOG_INFO  = 1           # Information Event
LOG_WARN  = 2           # Warning Event
LOG_ERR   = 3           # Error Event
LOG_CRIT  = 4           # Critical Event
LOG_OVERWRITE = True    # Set this contstant to True if the SCRIPT_LOG
                        # should be overwritten, False if not

# End of Script Constants

# Initialize Forensic Logging

try:            
    # If LOG should be overwritten before
    # each run, the remove the old log
    if LOG_OVERWRITE:
        # Verify that the log exists before removing
        if os.path.exists(SCRIPT_LOG):
            os.remove(SCRIPT_LOG)

    # Initialize the Log include the Level and message
    logging.basicConfig(filename=SCRIPT_LOG, format='%(levelname)s\t:%(message)s', level=logging.DEBUG)

except:
    print ("Failed to initialize Logging")
    quit()

# End of Forensic Log Initialization

# Initialize CSV Output File
# Write Heading Line
try:
    csvOut = open(CSV, "w")
    csvOut.write("FileName, MD5 Hash, Match, Category \n")
except:
    print ("Failed to initialize CSV File  .. Make sure file is not open")
    quit()    
        
# Script Functions
'''
If you script will contain functions then insert them
here, before the execution of the main script.  This
will ensure that the functions will be callable from
anywhere in your script
'''

# Function: GetTime()
#
# Returns a string containing the current time
#
# Script will use the local system clock, time, date and timezone
# to calcuate the current time.  Thus you should sync your system
# clock before using this script
#
# Input: timeStyle = 'UTC', 'LOCAL', the function will default to 
#                    UTC Time if you pass in nothing.

def GetTime(timeStyle = "UTC"):

    if timeStyle == 'UTC':
        return ('UTC Time: ', time.asctime(time.gmtime(time.time()))) 
    else:
        return ('LOC Time: ', time.asctime(time.localtime(time.time())))

# End GetTime Function ============================    


# Function: LogEvent()
#
# Logs the event message and specified type
# Input: 
#        eventType: LOG_INFO, LOG_WARN, LOG_ERR, LOG_CRIT or LOG_DEBUG
#        eventMessage : string containing the message to be logged


def LogEvent(eventType, eventMessage):

    if type(eventMessage) == str:
        try:

            timeStr = GetTime('UTC')
            # Combine current Time with the eventMessage
            # You can specify either 'UTC' or 'LOCAL'
            # Based on the GetTime parameter

            eventMessage = str(timeStr)+": "+eventMessage

            if eventType == LOG_INFO:
                logging.info(eventMessage)

            elif eventType == LOG_DEBUG:
                logging.debug(eventMessage)

            elif eventType == LOG_WARN:
                logging.warning(eventMessage)

            elif eventType == LOG_ERR:
                logging.error(eventMessage)

            elif eventType == LOG_CRIT:
                logging.critical(eventMessage)

            else:
                logging.info(eventMessage)
        except:
            logging.warn("Event messages must be strings")
    else:
        logging.warn('Received invalid event message')

# End LogEvent Function =========================    

# Simple CSV Write Method
# Without Library Assist

def WriteCSV(fileName, MD5, match, category):
    if match:
        csvOut.write(fileName+","+MD5+","+ "*** YES ***"+","+category+"\n")
    else:
        csvOut.write(fileName+","+MD5+","+ " "+","+""+"\n")
        
      
    

# Main Script Starts Here
#
# Script Overview
#
# The purpose of this script it to provide an example
# script that demonstrate and leverage key capabilities 
# of Python that provides direct value to the 
# forensic investigator.

if __name__ == '__main__':

    # Mark the starting time of the main loop
    theStart = time.time()
    
    LogEvent(LOG_INFO, SCRIPT_NAME)
    LogEvent(LOG_INFO, SCRIPT_VERSION)
    LogEvent(LOG_INFO, "Script Started")

    # Print Basic Script Information
    # For MPE+ Scripts the length of the argument vector is
    # always 2  scriptName, path  
    
    if len(argv) == 2:
        scriptName, path = argv
    else:
        LogEvent(LOG_INFO, argv + " Invalid Command line")
        quit()
    
    LogEvent(LOG_INFO,"Command Line Argument Vector")
    LogEvent(LOG_INFO,"Script Name: " + scriptName)
    LogEvent(LOG_INFO,"Script Path: " + path)
    
    # Verify the path exists and determine
    # the path type
    LogEvent(LOG_INFO, "Processing Command Line") 
    
    if os.path.exists(path):
        LogEvent(LOG_INFO,"Path Exists")
        if os.path.isdir(path):
            LogEvent(LOG_INFO,"Path is a directory")
        else:
            LogEvent(LOG_ERR, path + " is not a directory")
            quit()
    else:
        LogEvent(LOG_ERR, path + " Does not exist")    
        quit()

    LogEvent(LOG_INFO, "Reading Hash Values to Search from: "+SRC_HASH) 
    LogEvent(LOG_INFO, "Creating Dictionary of Hashes")
    
    hashDict = {}
    try:
        with open(SRC_HASH) as srcHashes:
            # for each line in the file extract the hash and id
            # then store the result in a dictionary
            # key, value pair
            # in this case the hash is the key and id is the value
    
            LogEvent(LOG_INFO, "Hashes included in Search")
            LogEvent(LOG_INFO, "========== HASHES INCLUDED IN SEARCH ==========")
            
            for eachLine in srcHashes:
                if eachLine != "END":
                    lineList = eachLine.split()
                    if len(lineList) >= 2:
                        hashKey = lineList[0].upper()
                        hashValue = ""
                        for eachElement in lineList[1:]:
                            hashValue = hashValue + " " + str(eachElement)
                            
                        # Strip the newline from the hashValue
                        hashValue  = hashValue.strip()
                        
                        # Add the key value pair to the dictionary
                        if hashKey not in hashDict:
                            hashDict[hashKey] = hashValue
                            LogEvent(LOG_INFO, hashKey+": "+hashValue)
                        else:
                            LogEvent(LOG_WARN, "Duplicate Hash Found: " + hashKey)
                    else:
                        # Not a valid entry, continue to next line
                        continue
                else:
                    break
            LogEvent(LOG_INFO, "==========    END HASH SEARCH LIST   ==========")
            
    except:
        LogEvent(LOG_ERR, "Failed to load Hash List: "+SRC_HASH)
        
    LogEvent(LOG_INFO, "========== FILE SEARCH START ==========")
    
    # Create Empty matchList and filesProcessed Count
    matchList = []
    filesProcessed  = 0
    
    # Now process all files in the directory provided
    # Including all subdirectories
    
    for root, subdirs, files in os.walk(path):
        
        for curFile in files:
            # Create the full pathName
            fullPath = os.path.join(root, curFile)
            
            # Generate the hash for the current file
            # Default is to use MD5
            hasher = hashlib.md5()
            with open(fullPath, 'rb') as theTarget:
                
                filesProcessed += 1
                
                # Read the contents of the file and hash them
                fileContents = theTarget.read()
                hasher.update(fileContents)
                
                # get the resulting hashdigest
                hashDigest = hasher.hexdigest().upper()
                
            # Now check for a hash match against the 
            # list we read in by checking the contents of the dictionary
            
            if hashDigest in hashDict: 
                # If we find a match log the match and add the match to the matchList
                matchDetails = hashDict[hashDigest]
                LogEvent(LOG_CRIT, "*** HASH MATCH File *** ")
                LogEvent(LOG_CRIT, "    MATCH File >> "+ curFile)
                LogEvent(LOG_CRIT, "    MD5 DIGEST >> "+ hashDigest)
                LogEvent(LOG_CRIT, "    CATEGORGY  >> "+ matchDetails)
                
                # add entry to match list
                matchList.append([curFile, hashDigest, matchDetails])
                
                # add entry to the csv file
                WriteCSV(curFile,hashDigest,True, matchDetails)
            else:
                # if no match simply log the file and associated hash value
                LogEvent(LOG_INFO, "File >> " + curFile + "   MD5 >> " + hashDigest)
                
                # add entry to csv file
                WriteCSV(curFile,hashDigest,False, "")

    # All files are processed
    # close the CSV File for good measure    
    csvOut.close()
    
    # Post the end of file search to the log
    LogEvent(LOG_INFO, "========== FILE SEARCH END ==========")        
    
    # Once we process all the files
    # Log the contents of the match list 
    # at the end of the log file
    
    # If any matches were found create a summary at
    # the end of the log
    if matchList:
        LogEvent(LOG_INFO, "")
        LogEvent(LOG_CRIT, "==== Matched Hash Summary Start ====")
        
        for eachItem in matchList:
            LogEvent(LOG_CRIT, "*** HASH MATCH File *** ")
            LogEvent(LOG_CRIT, "    MATCH File >> "+ eachItem[0])
            LogEvent(LOG_CRIT, "    MD5 DIGEST >> "+ eachItem[1])
            LogEvent(LOG_CRIT, "    CATEGORGY  >> "+ eachItem[2])            
            
        LogEvent(LOG_CRIT, "==== Matched Hash Summary End ====")

        
    # Record the End Time and calculate the elapsed time
    theEnd = time.time()
    elapsedTime = theEnd - theStart
    
    # Log the number of Files Processed
    # and the elapsed time
    
    LogEvent(LOG_INFO, 'Files Processed: ' + str(filesProcessed))
    LogEvent(LOG_INFO, 'Elapsed Time: '    + str(elapsedTime) + ' seconds')

    # Now print the contents of the forensic log
    
    with open(SCRIPT_LOG, 'r') as logData:
        for eachLine in logData:
            print(eachLine)





