''' 
Copyright (c) 2016 Python Forensics and Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Revision History

v .95 Beta  Initial Release (May 2016)
v .90 Alpha Initial Release Command Line Version (November 2015)

Writter for:
Python 2.6.x or greater (not Python 3.x)

pfDiscover Support File

Includes the FileExaminer Class

'''

# Required Python Import Standard Library Modules
import os           # OS Module
import re           # Regular Expression Modules
import time         # Time Module
import traceback    # raceback exception Module

# Psuedo Constants

MAXBUFF = 1024 * 1024 * 16   # 16 Megabytes defines the size of 
                             # of the memory chunks read
    
# Class: FileExaminer Class
#
# Desc: Handles all methods related to File Based Forensics
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
        self.mactimes   = ["","",""]
        self.fileSize   = 0
        self.fileOpen   = False
        self.fileType   = "unknown"
        self.uid        = 0
        self.gid        = 0
        self.mountPoint = False
        self.fileRead   = False
        self.md5        = ""
        self.sha1       = ""
        self.path       = theFile        
        self.sha256     = ""
        self.sha512     = ""
        self.zipLookup  = False
        
        self.emailDict = {}      # Create empty dictionaries
        self.ssnDict   = {}
        self.urlDict   = {}       
        self.pwDict    = {}
        self.ccDict    = {}
        self.usphDict  = {}
        self.zipDict   = {}
        self.zipDB     = {}
        
        try:
            
            if os.path.exists(theFile):
                # get the file statistics
                theFileStat =  os.stat(theFile)
                
                # get the MAC Times and store them in a list
                
                self.macTimes = []
                self.macTimes.append(time.ctime(theFileStat.st_mtime))
                self.macTimes.append(time.ctime(theFileStat.st_atime))
                self.macTimes.append(time.ctime(theFileStat.st_ctime))
                
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
                    
                    # Open the file to make sure we can access it
                    self.fp = open(theFile, 'rb')
                    
                    self.fileOpen = True
                
                else:
                    self.fileRead = False
                    
                try:
                    # Required zipdb comma separated value
                    # file containing zipcode to city lookup
                    with open("zipdb.csv", 'r') as zipData:
                        for line in zipData:
                            line=line.strip()
                            lineList = line.split(',')
                            if len(lineList) == 3:
                                key = lineList[0]
                                val = lineList[1:]
                                self.zipDB[key] = val
                        self.zipLookup = True
                except:
                    traceback.print_exc()
                    self.zipLookup = False
                      
            else:
                self.lastError = "File does not exist"
                
        except:
            self.lastError = "File Exception Raised"        
             

    # Function to Iterate through a large file
    # the file was opened during init
    
    def readBUFF(self):
        
        # Read in a bytearray
        ba = bytearray(self.fp.read(MAXBUFF))  
        
        # substitute spaces for all non-ascii characters
        # this improves the performance and accuracy of the
        # regular expression searches 
        
        txt = re.sub('[^A-Za-z0-9 ~!@#$%^&*:;<>,.?/\-\(\)=+_]', ' ', ba)

        # Return the resulting text string that will be searched
        return txt     

    #searches file for patterns matching
    
    # e-mails
    # SSN
    # URL
    # U.S. Phone Numbers
    # U.S. Postal Codes
    # Strong Passwords
    # Credit Card Numbers
    
    
    def scanMem(self, quiet):
        
        if not quiet:
            print "\nScanning Memory Image "
            
        # compile the regular expressions
        
        usphPattern     = re.compile(r'(1?(?: |\-|\.)?(?:\(\d{3}\)|\d{3})(?: |\-|\.)?\d{3}(?: |\-|\.)?\d{4})')
        emailPattern    = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}')  
        ssnPattern      = re.compile(r'\d{3}-\d{2}-\d{4}')
        urlPattern      = re.compile(r'\w+:\/\/[\w@][\w.:@]+\/?[\w\.?=%&=\-@/$,]*')
        pwPattern       = re.compile(r'[A-Za-z0-9~!@#$%^&*;:]{6,12}')
        ccPattern       = re.compile(r'(3[47]\d{2}([ -]?)(?!(\d)\3{5}|123456|234567|345678)\d{6}\2(?!(\d)\4{4})\d{5}|((4\d|5[1-5]|65)\d{2}|6011)([ -]?)(?!(\d)\8{3}|1234|3456|5678)\d{4}\7(?!(\d)\9{3})\d{4}\7\d{4})')
        zipPattern      = re.compile(r'(?!00[02-5]|099|213|269|34[358]|353|419|42[89]|51[789]|529|53[36]|552|5[67]8|5[78]9|621|6[348]2|6[46]3|659|69[4-9]|7[034]2|709|715|771|81[789]|8[3469]9|8[4568]8|8[6-9]6|8[68]7|9[02]9|987)\d{5}')
        
        cnt = 0
        gbProcessed = 0
    
        # Iterate through the file one chunk at a time
        
        for bArray in iter(self.readBUFF, ''):

            # Provides user feedback one dot = 16MB Chunk Processed
            if not quiet:
                if cnt < 64:
                    cnt +=1
                    print '.',
                else:
                    # Print GB processed 
                    gbProcessed += 1
                    print
                    print "GB Processed: ", gbProcessed
                    cnt = 0
                    
            # Perform e-mail search    
            try:
                # email
                partialResult = emailPattern.findall(bArray)
                for key in partialResult:
                    key = str(key)
                    # Keep track of the number of occurrences
                    if key in self.emailDict:
                        curValue = self.emailDict[key]
                        curValue +=1
                        self.emailDict[key] = curValue
                    else:
                        curValue = 1
                        self.emailDict[key] = curValue
                        
            except:
                traceback.print_exc()
                curValue = 1
                self.emailDict[key] = curValue 
            
            # Search for Strong Passwords
            try:
                # Password
                partialResult = pwPattern.findall(bArray)
                
                for key in partialResult:
                    key = str(key)

                    upper=0
                    lower=0
                    number=0
                    special=0
                    
                    for eachChr in key:
                        if eachChr in "abcdefghijklmnopqrstuvwxyz":
                            lower = 1
                        elif eachChr in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                            upper = 1
                        elif eachChr in '1234567890':
                            number = 1
                        elif eachChr in '~!@#$%^&*':
                            special = 1

                    if upper == 1 and lower == 1 and number == 1:
                        # Keep track of the number of occurrences    
                        if key in self.pwDict:
                            curValue = self.pwDict[key]
                            curValue +=1
                            self.pwDict[key] = curValue
                        else:
                            curValue = 1
                            self.pwDict[key] = curValue
            except:
                curValue = 1
                self.emailDict[key] = curValue 
                
            # Search for possible SS#    
            try:       
                # ssn
                partialResult = ssnPattern.findall(bArray)
                for key in partialResult:
                    key = str(key)
                    # Keep track of the number of occurrences
                    if key in self.ssnDict:
                        curValue = self.ssnDict[key]
                        curValue +=1
                        self.ssnDict[key] = curValue
                    else:
                        curValue = 1
                        self.ssnDict[key] = curValue
            except:
                curValue = 1
                self.ssnDict[key] = curValue        
            
            # Search for URL's
            try:    
                # url
                partialResult = urlPattern.findall(bArray)
                for key in partialResult:
                    key = str(key)
                    if key in self.urlDict:
                        curValue = self.urlDict[key]
                        curValue +=1
                        self.urlDict[key] = curValue
                    else:
                        curValue = 1
                        self.urlDict[key] = curValue        
            except:
                    curValue = 1
                    self.urlDict[key] = curValue 
                    
            # Search for Credit Cards
            try:    
               # Credit Card
                partialResult = ccPattern.findall(bArray)
                # Keep track of the number of occurrences
                for key in partialResult:
                    key=str(key[0])
                    key = key.translate(None, '- ')
                    if key in self.ccDict:
                        curValue = self.ccDict[key]
                        curValue +=1
                        self.ccDict[key] = curValue
                    else:
                        curValue = 1
                        self.ccDict[key] = curValue        
            except:
                curValue = 1
                self.ccDict[key] = curValue 

            # Search for Phone Numbers
            try:    
                # Phone Number
                partialResult = usphPattern.findall(bArray)
                
                for key in partialResult:
                    key = str(key)
                    key = key.strip()
                    if key[0] in '23456789\(':
                        # Keep track of the number of occurrences
                        if key in self.usphDict:
                            curValue = self.usphDict[key]
                            curValue +=1
                            self.usphDict[key] = curValue
                        else:
                            curValue = 1
                            self.usphDict[key] = curValue        
            except:
                curValue = 1
                self.usphDict[key] = curValue 

            # Search for valid US Postal Codes
            try:    
                # Valid US Postal Codes
                partialResult = zipPattern.findall(bArray)
                for key in partialResult:
                    key = str(key)
                    # Keep track of the number of occurrences
                    if key in self.zipDict:
                        curValue = self.zipDict[key]
                        curValue +=1
                        self.zipDict[key] = curValue
                    else:
                        curValue = 1
                        self.zipDict[key] = curValue        
            except:
                curValue = 1
                self.zipDict[key] = curValue 
                
        return True

    def printEmails(self):
        
        print "\nPossible E-Mails"
        print "================\n"
        
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.emailDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]
    
    def printURLs(self):
        
        print "\nPossible URLs"
        print "=============\n"        
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.urlDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]        
            
    def printSSNs(self):
        print "\nPossible SSNs"
        print "=============\n"                
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.ssnDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]  
 
    def printPWs(self):
        print "\nPossible PWs"
        print "=============\n"                
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.pwDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]         

    def printCCs(self):
        print "\nPossible Credit Card #s"
        print "=======================\n"                
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.ccDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]   
            
    def printUSPHs(self):
        print "\nPossible U.S. Phone #s"
        print "=====================\n"                
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.usphDict.items()], reverse = True)]  
        for entry in sortedList:
            print '%5d' % entry[1], '%s' % entry[0]   
            
    def printZIPs(self):
        
        print "\nPossible Valid U.S. Postal Codes"
        print "================================\n"  
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.zipDict.items()], reverse = True)]  
        
        # If the zipLookup Dictionary is available
        # Obtain the associated City
        # if lookup fails, skip possible ZipCode
        
        if self.zipLookup:
            for entry in sortedList:
                if entry[0] in self.zipDB:
                    valList = self.zipDB[entry[0]]
                    print '%5d' % entry[1], '%s' % entry[0], '%s' % valList[0], '%s' % valList[1]    
        else:            
            for entry in sortedList:
                print '%5d' % entry[1], '%s' % entry[0]          
            
    def csvEmails(self):
        
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvEmail.csv", 'w')
            tempList = ['Count', 'Possible E-mails']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvEmail.csv"
        
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.emailDict.items()], reverse = True)] 
        
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")  
        
        csvFile.close()
        
    
    def csvURLs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvURL.csv", 'w')
            tempList = ['Count', 'Possible URLs']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvURL.csv"
    
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.urlDict.items()], reverse = True)]  
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")    

        csvFile.close()
            
    def csvSSNs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvSSN.csv", 'w')
            tempList = ['Count', 'Possible SSNs']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvSSN.csv"
          
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.ssnDict.items()], reverse = True)]  
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")  
    
        csvFile.close()
    
    def csvPWs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvPW.csv", 'w')
            tempList = ['Count', 'Possible Strong Passwords']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvPW.csv"
           
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.pwDict.items()], reverse = True)]  
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")     
            
        csvFile.close()
 
    def csvCCs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvCC.csv", 'w')
            tempList = ['Count', 'Possible Credit Cards']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvCC.csv"
           
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.ccDict.items()], reverse = True)]  
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")   
 
    def csvUSPHs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvUSPH.csv", 'w')
            tempList = ['Count', 'Possible U.S. Phone Numbers']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvUSPH.csv"
           
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.usphDict.items()], reverse = True)]  
        for entry in sortedList:
            outStr = ",".join([str(entry[1]), entry[0]])
            csvFile.write(outStr)
            csvFile.write("\n")      
            
        csvFile.close()

    def csvZIPs(self):
        # Open CSV File and Write Header Row
        try:
            csvFile = open("csvZIP.csv", 'w')
            tempList = ['Count', 'Possible Valid U.S.Postal Codes']
            outStr = ",".join(tempList)
            csvFile.write(outStr)
            csvFile.write("\n")
        except:
            print "Cannot Open File for Write: csvZIP.csv"
           
        sortedList = [(k,v) for v,k in sorted([(v,k) for k,v in self.zipDict.items()], reverse = True)]  

        # If the zipLookup Dictionary is available
        # Obtain the associated City
        # if lookup fails, skip possible ZipCode

        if self.zipLookup:
            for entry in sortedList:
                if entry[0] in self.zipDB:
                    valList = self.zipDB[entry[0]]
                    outStr = ",".join([str(entry[1]), entry[0], valList[0], valList[1]])
                    csvFile.write(outStr)
                    csvFile.write("\n")                       
        else:        
            for entry in sortedList:
                outStr = ",".join([str(entry[1]), entry[0]])
                csvFile.write(outStr)
                csvFile.write("\n")      
            
        csvFile.close()
        
    def __del__(self):
        return

# End Forensic File Class ====================================
