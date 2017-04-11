'''
Copyright (c) 2015 Chet Hosmer, cdh@python-forensics.org

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

'''
#
# P2NMA-Analyze.py Script
# 
# Perform analysis of previously capture .ipdict files
#
#
# Version 1.0 February 17-2015

import argparse         # Python Standard Library - Parser for command-line options, arguments
import os               # operating system functions i.e. file I/o
import datetime         # Python Standard Library date and time methods
import pickle           # Python Standard Library pickle methods
import socket           # Python Standard Library Low Level Networking
import sys              # Python Standard Library Low Level System Methods

# PSUEDO CONSTANTS

PRINT_STDOUT   = True   # If True, all output and menu selections directed 
                        # If False, all output directed to a file except menu 
                        
OUT            = sys.stdout        # Default Output to Standard Out


#  
# Class: OSObservationDictionary
#
# Desc: Handles all methods and properties
#       relating to the OSObservations 
#
#

class OSObservationDictionary:

    # Constructor
    
    def __init__(self):
        
        #Attributes of the Object
        
        self.Dictionary = {}            # Dictionary to Hold IP Observations
        self.osObservationFileName = ""
        self.osObservationsLoaded  = False  
        

    def LoadOb(self, fileName):
        try:
            with open(fileName, 'rb') as fp:
                self.Dictionary = pickle.loads(fp.read())
                self.observationFileName = fileName
                self.observationsLoaded  = True  
        except:
            print "Loading OS Observations File - Failed"
            self.osObservationsLoaded  = False
            self.osObservationFileName = ""
            
        # Method to retrieve an observation
    # If no observation found return None
    
    def GetOb(self,key):
        
        if key in self.Dictionary:
            curValue = self.Dictionary[key]
            return curValue
        else:
            return None
        
    def GetAllObservations(self):
        
        observationList = []
        
        sorted = self.Dictionary.items()
        sorted.sort()
        
        for k, v in sorted:
            observationList.append(k)
            
        return observationList

    def PrintOb(self):
        
        print >> OUT, "\nOS Observations"
        print >> OUT, "Unique Combinations:    ", str(len(self.Dictionary))
        print >> OUT
        
        
        # Print Heading
        print >> OUT, '                                          ',
        print >> OUT, "|-------------------------------------------  Hourly Observations  ---------------------------------------------------|"
        
        print >> OUT, '%16s' % "Server",
        print >> OUT, '%4s'  % "TOS",
        print >> OUT, '%4s'  % "TTL",
        print >> OUT, '%6s'  % "DF",
        print >> OUT, '%7s'  % "Window",
        
        for i in range(0, 24):
            print >> OUT,  ' ',            
            print >> OUT, '%02d' % i,
        print >> OUT, "\n-----------------------------------------------------------------------------------------------------------------------------------------------------------------"
        
        sorted = self.Dictionary.items()
        sorted.sort()
        
        # Print Contents
        for keys,values in sorted:
            print >> OUT, '%16s' % keys[0],
            print >> OUT, '%4s'  % str(keys[1]),
            print >> OUT, '%4s'  % str(keys[2]),
            print >> OUT, '%6s'  % str(keys[3]),
            print >> OUT, '%7s'  % str(keys[4]),
            
            for i in range(0, 24):
                print >> OUT, '%4s' % str(values[i]),
            print >> OUT
            
    # End Print OS Observations
            
    # Load in and Observation Dictionary
    # from the specified file
    
    def LoadOb(self, fileName):
        
        try:
            with open(fileName, 'rb') as fp:
                self.Dictionary = pickle.loads(fp.read())
                self.osObservationFileName = fileName
                self.osObservationsLoaded  = True  
        except:
            print "Loading Observations - Failed"
            self.osObservationsLoaded  = False
            self.osObservationFileName = ""        

        
    # Destructor Delete the Object
    
    def __del__(self):
        print >> OUT, "OS Observation Dictionary Closed"
        
# End OSObservationClass ====================================

class FingerPrint:

    # Constructor
    
    def __init__(self):
        
       
        self.classificationList = []
        
        self.osObservationsLoaded  = False
        self.osObservationFileName = ""
        self.osTruthTableLoaded = False
        self.osTruthTableFileName = ""
    
    # Load in the TruthTable from the userdefined text file
    
    def LoadTruthTable(self, truthTable):
        
        # String Index Values
        
        TTL_RANGE   = 0
        TOS         = 1
        DF          = 2
        WINDOW_SIZE = 3
        OS          = 4
        CHK_FLD     = 5
        
        tableErrors = False
        
        try:
            # Process the User Defined Input Table
            
            with open(truthTable, "r") as fileContents:
                
                for eachLine in fileContents:
                    
                    values = eachLine.split()
                    
                    # Make sure we have the proper number of fields
                    # in this line
                    
                    if len(values) == CHK_FLD:
                        # convert the text ttl and winsize into low and high integers
                        # unless wild card specified
                        if values[TTL_RANGE] != '*':
                            ttlLow, ttlHigh = self.convertRange(values[TTL_RANGE])
                        else:
                            ttlLow = -1
                            ttlHgh = -1
                            
                        if values[WINDOW_SIZE] != '*':
                            winLow, winHigh = self.convertRange(values[WINDOW_SIZE]) 
                        else:
                            winLow  = -1
                            winHigh = -1
                        
                        #  Convert TOS to an integer, unless wild card
                        if values[TOS] == '*':
                            tosVal = '*'
                        else:
                            try:
                                tosVal = int(values[TOS])
                            except:
                                # invalid TOS value
                                # skip this line
                                tableErrors = True
                                continue
                        
                        # Convert DF to True or False or wild card
                        if values[DF].upper()   == "Y":
                            dfVal = True
                        elif values[DF].upper() == "N":
                            dfVal = False
                        elif values[DF] == '*':
                            dfVal = "*"
                        else:
                            # invalid DF value
                            # skip this line
                            tableErrors = True
                            continue
                        
                        if ttlLow != None and winLow != None:
                            self.classificationList.append( [ttlLow, ttlHigh, tosVal, dfVal, winLow, winHigh, values[OS]] )
                        else:
                            tableErrors = True
                            
            self.osTruthTableLoaded   = True
            self.osTruthTableFileName = truthTable
            
        except:
            print "***** Loading Truth Table - Failed *****"
            self.osTruthTableLoaded = False
            self.osTruthTableFileName = ""
            
        # Return to caller with errors flag
        # True  = Errors Found in Text File
        # False = All Rows Loaded Properly
        
        return tableErrors     
    
    # End LoadTruthTable Method        
         
    # Convert Range Method
    # Used to Convert range values 123-456
    # into two integer values
    
    def convertRange(self, theString):

        lowStr = ""
        hghStr = ""
        
        # parse the low value
        for x in range(0,len(theString)):
            if theString[x].isdigit():
                lowStr += theString[x]
            else:
                break
        # Skip the delimeters usually comma or dash
        for s in range(x, len(theString)):
            if theString[s].isdigit():
                break
            else:
                continue
            
        # If we are not at the end
        if s < len(theString):
            # parse the high value
            for y in range(s, len(theString)):
                if theString[y].isdigit():
                    hghStr += theString[y]
                else:
                    break
        else:
            return None, None                   

        # If we have two strings, then convert to ints
        
        if len(lowStr) > 0 and len(hghStr) > 0:
            lowVal = int(lowStr)
            hghVal = int(hghStr)
        else:
            return None, None
        
        # Finally,
        # If we have a proper low high relationship return the ints
        if lowVal <= hghVal:
            return lowVal, hghVal
        else:
            return None, None
        
    # End convertRange Method
    
    
    # GetOSClassification Searches the Loaded Truth Table
    # for a match, it will return on the first successful match
    # if no match is found it will return the string "UNDEFINED"
    
    def GetOSClassification(self, ttl, tos, df, winSize):
        
        # List Index
        
        TTL_LOW     = 0
        TTL_HGH     = 1
        TOS_VAL     = 2
        DF_VAL      = 3
        WIN_LOW     = 4
        WIN_HGH     = 5
        OS_VAL      = 6
        
        # Search the classificationList (TruthTable)
        
        for entry in self.classificationList:
            
            # First Check the TTL Value, if in Range continue
            if ( (entry[TTL_LOW] <= ttl and entry[TTL_HGH] >= ttl) or (entry[TTL_LOW] == '*') ):
                # Next Check the Type of Service Value, if Match Continue
                if entry[TOS_VAL] == tos  or entry[TOS_VAL] == "*":
                    # Next Check the DF Flag, if Match Continue
                    if entry[DF_VAL] == df or entry[DF_VAL] == "*":
                        # Finally, check the Window Size, if in Range Continue
                        if ( (entry[WIN_LOW] <= winSize and entry[WIN_HGH] >= winSize) or (entry[WIN_LOW] == '*') ):
                            # Return the OS Value Found
                            return entry[OS_VAL]
        
        # If none of the rules result in a match
        return "UNDEFINED"
    
    # End GetOSClassification Method
    
    
    # PrintTruthTable Method
    # Print out the currently loaded Truth Table
    
    def PrintTruthTable(self):
        
        TTL_LOW     = 0
        TTL_HGH     = 1
        TOS_VAL     = 2
        DF_VAL      = 3
        WIN_LOW     = 4
        WIN_HGH     = 5
        OS_VAL      = 6
    
        print >> OUT,'\nCurrent Loaded Fingerprint Truth Table\n'
        print >> OUT,'%10s ' % 'TTL RANGE',
                                   
        print >> OUT,'%4s ' % 'TOS',
        print >> OUT,'%5s ' % ' DF ',

        print >> OUT,'%16s ' % 'WIN RANGE',
        
        print >> OUT,'%22s ' % 'OS Fingerprint'
        print >> OUT,'================================================================='

        for entry in self.classificationList:
            
            print >> OUT,'%3s ' % str(entry[TTL_LOW]),
            print >> OUT, "-",
            print >> OUT,'%3s ' % str(entry[TTL_HGH]),
                                       
            print >> OUT,'%4s ' % str(entry[TOS_VAL]),
            print >> OUT,'%5s ' % str(entry[DF_VAL]),

            print >> OUT,'%6s ' % str(entry[WIN_LOW]),
            print >> OUT, "-",
            print >> OUT,'%6s ' % str(entry[WIN_HGH]),
            
            print >> OUT,' %20s '% entry[OS_VAL]
    
        print >> OUT, '\n\n'
            
    # End PrintTruthTable Method
    
    
    # Print the OS Fingerprint Analysis Menu
    
    def PrintOSAnalysisMenu(self, osState, osFile):
        
        print "\n========== P2NMAP OS Fingerprint Analyze Menu ==========\n"
        
        if osState:
            print "Current Observation File: ", osFile
        if self.osTruthTableLoaded:
            print "Current OS Truth Table:   ", self.osTruthTableFileName
        
        print

        print "[L]    Load Observation File for Analysis" 
        print "[T]    Load Observation Truth Table" 
        
        if osState and self.osTruthTableLoaded:
            
            if PRINT_STDOUT:
                print "[O]    Direct Output to File   (Current = Stdout)"
            else:
                print "[O]    Direct Output to Stdout (Current = results.txt)"
                            
            print "============================================================="    
            print "[1]    Print Truth Table"
            print "[2]    Print Observations"
            print "[3]    Print Probable OS Fingerprint "
            print
        print "[X]    Exit P2NMAP Fingerprint Analysis"
        print    

# End FingerPrint Class ====================================

    
    
#===================================
# Main Program Starts Here
#===================================

if __name__ == '__main__':
    
    # Local Psuedo Constants
    IP  = 0
    TOS = 1    
    TTL = 2
    DF  = 3
    WIN = 4
    
    # Instantiate the FingerPrint and OSObservationDictionary Objects
    fpOB = FingerPrint()
    osOB = OSObservationDictionary()
    
    # Process User Input
    while True:
        fpOB.PrintOSAnalysisMenu(osOB.osObservationsLoaded, osOB.osObservationFileName)
        menuSelection = raw_input("Enter Selection: ").upper()
        
        # Attempt to Load the OS Capture File
        if menuSelection == 'L':
            fileName = raw_input("Enter OS Capture File: ")
            osOB.LoadOb(fileName)
            print
     
        # Attempt to Load a Truth Table
        elif menuSelection == 'T':
            fileName  = raw_input("Enter Truth Table File: ")
            rowErrors = fpOB.LoadTruthTable(fileName)
            
            # If Table Loaded, then check for row errors
            if fpOB.osTruthTableLoaded:
                # If rowError then inform the user
                if rowErrors:
                    print >> OUT, "Table Loaded but with Errors, Check Truth Table Input"
                else:
                    print >> OUT, "Truth Table Loaded"            
                print   
        
        # Toggle the Current Output State    
        elif menuSelection == 'O':
            if PRINT_STDOUT:
                PRINT_STDOUT = False
                OUT = open("results.txt", 'w+')
            else:
                PRINT_STDOUT = True  
                OUT.close()
                OUT = sys.stdout
        
        # Print Out the Current Truth Table
        
        elif menuSelection == '1':
            fpOB.PrintTruthTable()


        # Print out the Current Observation List
        elif menuSelection == '2':
            osOB.PrintOb()
        
        # Process the Observation List and 
        # Print out Server Type
        # By matching the observed value list with
        # the loaded Truth Table
        
        elif menuSelection == '3':
            
            obList = osOB.GetAllObservations()
            
            print >> OUT
            print >> OUT,'%16s ' % 'IP Address',
            print >> OUT,'%25s ' % 'Fingerprint OS Type'
            print >> OUT,"============================================================="
            
            for entry in obList:
                osType = fpOB.GetOSClassification(entry[TTL], entry[TOS], entry[DF], entry[WIN])
                print >> OUT,'%16s ' % entry[IP],
                print >> OUT,'%25s ' % osType

                
        elif menuSelection == 'X':
            break
        else:
            print "Entry not recognized"
            continue
    
    OUT.flush()

print "done"
    
    
     
            
        
                                           
                    

