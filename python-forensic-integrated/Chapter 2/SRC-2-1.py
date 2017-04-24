
'''
Copyright (c) 2016 Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Script Purpose: Forensic Template SRC-2-1
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
SCRIPT_NAME    = "Script: Forensic Example Script One SRC-2-1"
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
        return ('UTC Time:  ', time.asctime(time.gmtime(time.time()))) 
    else:
        return ('Local Time:', time.asctime(time.localtime(time.time())))
    
# End GetTime Function       


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
        
        
# End LogEvent Function       

# End of Script Functions

# Script Classes
'''
If you script will contain classes then insert them
here, before the execution of the main script.  This
will ensure that the functions will be accessible from
anywhere in your script
'''

# End of Script Classes


# Main Script Starts Here

LogEvent(LOG_INFO, SCRIPT_NAME)
LogEvent(LOG_INFO, SCRIPT_VERSION)
LogEvent(LOG_INFO, "Script Started")

# Print Basic Script Information

print SCRIPT_NAME
print SCRIPT_VERSION
print SCRIPT_AUTHOR

utcTime = GetTime()
print "Script Started: ", utcTime

#
# Script Work
# for the template we just sleep 5 seconds
#

print "Performing Work"
time.sleep(5)

utcTime = GetTime('UTC')
print "Script   Ended: ", utcTime

LogEvent(LOG_DEBUG, 'Test Debug')
LogEvent(LOG_WARN,  'Test Warning')
LogEvent(LOG_ERR,   'Test Error')
LogEvent(LOG_CRIT,  'Test Critical')

LogEvent(LOG_INFO,  'Script Ended')

# End of Script Main







