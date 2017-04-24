
'''
Copyright (c) 2016 Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Script Purpose: Forensic File Processing, Hashing and Image Rendering
Script Version: 1.0
Script Author:  C.Hosmer

Script Revision History:
Version 1.0 March 2016 

'''
# Script Module Importing

# Python Standard Library Modules
import os           # Operating/Filesystem Module
import time         # Basic Time Module
import logging      # Script Logging
import hashlib      # Cryptographic Hashing
import argparse     # Command Line Processing Module


# Import 3rd Party Modules

from PIL import Image

# End of Script Module Importing


# Script Constants

'''
Python does not support constants directly
however, by initializing variables here and
specifying them as UPPER_CASE you can make your
intent known
'''
# General Constants
SCRIPT_NAME    = "Script: Forensic Script Two SRC-2-2.py"
SCRIPT_VERSION = "Version 1.0"
SCRIPT_AUTHOR  = "Author: C. Hosmer, Python Forensics"
SCRIPT_LOG     = "./FORENSIC_LOG.txt"

# LOG Constants used as input to LogEvent Function
LOG_DEBUG = 0           # Debugging Event
LOG_INFO  = 1           # Information Event
LOG_WARN  = 2           # Warning Event
LOG_ERR   = 3           # Error Event
LOG_CRIT  = 4           # Critical Event
LOG_OVERWRITE = True    # Set this contstant to True if the SCRIPT_LOG
                        # should be overwritten, False if not

# End of Script Constants


# Initialize the Forensic Log

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
    print "Failed to initialize Logging"
    quit()

# End of Forensic Log Initialization

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
            print "Event Logging Failed"
    else:
        logging.warn('Received invalid event message')


# End LogEvent Function =========================    

#
# Name: ParseCommandLine() Function
#
# Process and Validate the command line arguments
# using the Python Standard Library module argparse
#
# Input: none
#
# Return: validated filePath and hashType
#         or generate a detailed error

def ParseCommandLine():
      
    parser = argparse.ArgumentParser(SCRIPT_NAME)
    parser.add_argument('-p', '--scanPath', type= ValPath, required=True, help="specifies the file path to scan")
    parser.add_argument('-t', '--hashType', type= ValHash, required=True, help="enter hashType MD5, SHA1, SH224, SHA256, SHA384 or SHA512")   

    theArgs = parser.parse_args()   

    return theArgs.scanPath, theArgs.hashType


# End ParseCommandLine ============================

#
# Name: ValidatePath Function
#
# Function validates validate a directory path 
# exists and readable.  Used for argument validation only
#
# Input: a directory path string
#  
# Returns the validated directory
# or raises command line errors
#

def ValPath(thePath):

    # Validate the path is a directory
    if not os.path.isdir(thePath):
        raise argparse.ArgumentTypeError('Path does not exist')

    # Validate the path is readable
    if os.access(thePath, os.R_OK):
        return thePath
    else:
        raise argparse.ArgumentTypeError('Path is not readable')

#End ValidateDirectory ===================================

#
# Name: ValHash Type Function
#
# Function validates the entered hash string
#
# Input: HashType
#  
# Returns the validated hashType upper case
# or raises command line errors
#

def ValHash(theAlg):

    theAlg = theAlg.upper()
    if theAlg in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']:
        return theAlg
    else:
        raise argparse.ArgumentTypeError('Invalid Hash Type Specified')

#End ValHash ===============================

# End of Script Functions

# Script Classes

# Class: FileExaminer Class
#
# Desc: Handles basic File Based Examination
# Methods  constructor:    Initializes the Forensic File Object and Collects Basic Attributes
#                          File Size
#                          MAC Times
#                          Reads file into a buffer
#          hashFile:       Generates the selected one-way hash of the file
#          destructor:     Deletes the Forensic File Object

class FileExaminer:

    # Constructor
    
    def __init__(self, theFile):
        
        #Attributes of the Object
        
        self.lastError  = "OK"
        
        # Modified Access Create Time
        self.mactimes   = ["","",""]
        
        filename, self.fileExtension = os.path.splitext(theFile)
        
        # File Status Data
        self.filePath   = theFile
        self.mode       = 0
        self.fileSize   = 0
        self.fileType   = "unknown"
        self.uid        = 0
        self.gid        = 0
        self.mountPoint = False
        self.fileRead   = False
        
        # Possible Hashes
        self.md5        = ""
        self.sha1       = ""
        self.sha224     = ""
        self.sha256     = ""
        self.sha384     = ""      
        self.sha512     = ""
        self.lastHash   = ""
        
        # Image data (if file is and image)
        self.imageHeight = 0
        self.imageWidth  = 0
        self.imageFormat = ''
        self.imageFormatDesc = ''
        self.imageExif = ''

        try:
            
            if os.path.exists(theFile):
                
                # get the file statistics
                theFileStat =  os.stat(theFile)
                
                # get the MAC Times and store them in a list
                
                self.macTimes = []
                self.macTimes.append(time.ctime(theFileStat.st_mtime))
                self.macTimes.append(time.ctime(theFileStat.st_atime))
                self.macTimes.append(time.ctime(theFileStat.st_ctime))
                self.mode = theFileStat.st_mode
                
                # get and store the File size
                
                self.fileSize = theFileStat.st_size
                
                # Get and store the ownership information
                
                self.uid = theFileStat.st_uid
                self.gid = theFileStat.st_gid
                
                if os.path.isfile(theFile):
                    self.fileType = "File"
                # Is this a real file?
                elif os.path.islink(theFile):
                    self.fileType = "Link"
                # Is This filename actually a directory?
                elif os.path.isdir(theFile):
                    self.fileType = "Directory"
                else:
                    self.fileType = "Unknown"
                
                # Is the pathname a mount point?
                if os.path.ismount(theFile):
                    self.mountPoint = True
                else:
                    self.mountPoint = False        
                
                # Is the file Accessible for Read?
                
                if os.access(theFile, os.R_OK) and self.fileType == "File":
                    
                    # Open the file
                    fp = open(theFile, 'rb')
                    
                    # Assume we have enough space 
                    self.buffer = fp.read()
                   
                    # Close the file we have the entire file in memory
                    fp.close()
                    
                    self.fileRead = True
                
                else:
                    self.fileRead = False
                    
            else:
                self.lastError = "File does not exist"
                
        except:
            self.lastError = "File Exception Raised"    
            LogEvent(LOG_ERR, "File Examiner - Failed to Process File: " + theFile)

    # Hash file method
    
    def hashFile(self,hashType):
        
        try:
            
            if hashType == "MD5":
                hashObj = hashlib.md5()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.md5 = self.lastHash
                self.lastHash 
                self.lastError = "OK"
                return True
            elif hashType == "SHA1":
                hashObj = hashlib.sha1()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.sha1 = self.lastHash
                self.lastError = "OK"
                return True
            if hashType == "SHA224":
                hashObj = hashlib.sha224()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.sha224 = self.lastHash
                self.lastError = "OK"
                return True
            elif hashType == "SHA256":
                hashObj = hashlib.sha256()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.sha256 = self.lastHash
                self.lastError = "OK"
                return True       
            if hashType == "SHA384":
                hashObj = hashlib.sha384()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.sha384 = self.lastHash
                self.lastError = "OK"
                return True
            elif hashType == "SHA512":
                hashObj = hashlib.sha512()
                hashObj.update(self.buffer)
                self.lastHash = hashObj.hexdigest().upper()
                self.sha512 = self.lastHash
                self.lastError = "OK"
                return True                
            else:
                self.lastError = "Invalid Hash Type Specified"
                return False
        except:
            self.lastError = "File Hash Failure"
            LogEvent(LOG_ERR, "File Hashing - Failed to Hash File")
            return False

    def ExtractImageProperties(self):
        
        try:
            image = Image.open(self.filePath)
            self.imageHeight = image.height
            self.imageWidth  = image.width
            self.imageFormat = image.format
            self.imageFormatDesc = image.format_description
            if self.imageFormat == 'JPEG':
                self.imageExif = image._getexif()
                
            return True
        except:
            self.lastError = "Error Processing Image Data"
            LogEvent(LOG_ERR, "Error Processing Image Data")
            return False
            
            
    def __del__(self):
        print 
        
# End Forensic File Class ====================================

# End of Script Classes


# Main Script Starts Here

#
# Script Overview
#
# The purpose of this script it to provide an example
# script that demonstrate and leverage key capabilities 
# of Python that provides direct value to the 
# forensic investigator.

# This script will perform the following:
#
# 1) Process the command line and obtain the filePath and hashType
# 2) The file names will be stored in a Python List object
# 3) for each file encountered meta-data will be extracted
#    and each file will be hashed with the selected algorithm.
#    the results will be written to the log file.

LogEvent(LOG_INFO, SCRIPT_NAME)
LogEvent(LOG_INFO, SCRIPT_VERSION)
LogEvent(LOG_INFO, "Script Started")

# Print Basic Script Information

print SCRIPT_NAME
print SCRIPT_VERSION
print SCRIPT_AUTHOR

utcTime = GetTime()
print "Script Started: ", utcTime
print

#
# STEP One:
# Parse the Command Line Arguments
#

thePath, theAlg = ParseCommandLine()

print "Path Selected: ", thePath
LogEvent(LOG_INFO, "Path Selected: "+thePath)

print "Algorithm Selected:", theAlg
LogEvent(LOG_INFO,"Algorithm Selected: "+ theAlg)

#
# Step Two extract a list of filenames
# from the path specified
#

listOfFiles = os.listdir(thePath)

#
# Step Three Extract the basic metadata and
#      specified file hash of the each file
#      using the FileExaminer Class
#

for eachFile in listOfFiles:
    
    # Utilize a try except loop in case encounter
    # Errors during file processing
    
    try:
        # join the path and file name
        fullPath = os.path.join(thePath, eachFile)
        
        # create a file examiner object
        feObj = FileExaminer(fullPath)
        
        # generate the specified hash
        if feObj.hashFile(theAlg):
            print "Hashing Success"
        else:
            print "Hashing Failed"
        
        # Extract image properties if file is an image
        if feObj.ExtractImageProperties():
            imageData = True
            print "Image Properties Extracted"
        else:
            imageData = False
            print "Image Property Extraction Failed"
            
        
        LogEvent(LOG_INFO, "============================================")
        LogEvent(LOG_INFO, "File Processed: "+ fullPath)       
        LogEvent(LOG_INFO, "File Extension: "+ feObj.fileExtension)           
        LogEvent(LOG_INFO, "File Modified:  "+ feObj.macTimes[0])   
        LogEvent(LOG_INFO, "File Accessed:  "+ feObj.macTimes[1])  
        LogEvent(LOG_INFO, "File Created:   "+ feObj.macTimes[2])  
        LogEvent(LOG_INFO, "File Size:      "+ str(feObj.fileSize))          
        LogEvent(LOG_INFO, "File Hash:      "+ theAlg + ":" + feObj.lastHash)
        LogEvent(LOG_INFO, "File Owner:     "+ str(feObj.uid))  
        LogEvent(LOG_INFO, "File Group:     "+ str(feObj.gid)) 
        LogEvent(LOG_INFO, "File Mode:      "+ bin(feObj.mode))
        
        if imageData:
            LogEvent(LOG_INFO, "Image Format:        "+ feObj.imageFormat)
            LogEvent(LOG_INFO, "Image Format Desc    "+ feObj.imageFormatDesc)
            LogEvent(LOG_INFO, "Image Width Pixels:  "+ str(feObj.imageWidth))
            LogEvent(LOG_INFO, "Image Height Pixels: "+ str(feObj.imageHeight))   
                
        print "=================================================="  
        print "File Processed: ", fullPath
        print "File   Ext:  ", feObj.fileExtension
        print "MAC  Times:  ", feObj.macTimes
        print "File  Size:  ", feObj.fileSize
        print "File  Hash:  ", theAlg, feObj.lastHash
        print "File Owner:  ", feObj.uid
        print "File Group:  ", feObj.gid
        print "File Mode:  ", bin(feObj.mode)
        print 
        
        if imageData:
            print "Image Properties"
            print "Image Format:        ", feObj.imageFormat
            print "Image Format Desc    ", feObj.imageFormatDesc
            print "Image Width Pixels:  ", feObj.imageWidth
            print "Image Height Pixels: ", feObj.imageHeight
            if feObj.imageFormat == "JPEG":
                print "Exif Raw Data:       ", feObj.imageExif

    except:
        print "File Processing Error: ", fullPath
        LogEvent(LOG_INFO, "File Processing Error: "+ fullPath)    
    
print
print "Files Processing Completed"    

LogEvent(LOG_INFO, "Script End")

utcTime = GetTime('UTC')
print "Script   Ended: ", utcTime


# End of Script Main







