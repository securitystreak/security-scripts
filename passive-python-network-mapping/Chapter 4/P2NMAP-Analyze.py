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
# P2NMAP-Analyze.py Script
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

# 3rd Party Libraries
import pygeoip          # 3rd Party Geo IP Lookup
                        # pip install pygeoip
                        # This product includes GeoLite data created by MaxMind, available from
                        # <a href="http://www.maxmind.com">http://www.maxmind.com</a>.                                 
                                 
# import matplotlib.pyplot as plt  # Import 3rd Party Plotting Library     

# DEFINE PSUEDO CONSTANTS

SERVER    = 0  # Server key index
CLIENT    = 1  # Client key index
PORT      = 2  # Port   key index
TYPE      = 3  # Type   key index ("TCP" or "UDP")
HOST_NAME = 0  # HOST NAME index return from gethostbyaddr

# Note these are set by menu selection

HOST_LOOKUP    = False  # gethostbyaddr() will obtain Host Name
COUNTRY_LOOKUP = False  # Country Name wil be associated with IP

PRINT_STDOUT   = True   # If True, all output and menu selections directed 
                        # If False, all output directed to a file except menu 
                        
OUT            = sys.stdout        # Default Output to Standard Out

OSOB_LOADED    = False             # OS Observations Loaded Flag

#
# Country Lookup
#

def GetCountry(ipAddr):
    
    # download from http://dev.maxmind.com/geoip/legacy/geolite/
    gi = pygeoip.GeoIP('geo.dat')
    return gi.country_name_by_addr(ipAddr)

# End GetCountry Function

#
# Name: ValFileRead
#
# Desc: Function that will validate a file exists and is readable 
#       Used for argument validation only
#
# Input: a file Path
#  
# Actions: 
#              if valid will return a full file path
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#

def ValFileRead(theFile):

    # Validate the path is a File
    if not os.path.exists(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    # Validate the path is Readable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')

#End ValFileRead ===================================

#
# Port Lookup Class
#
class PortsClass:

    # Constructor
    
    def __init__(self, portTextFile):
        
        #Attributes of the Object
        self.portDictionary = {}
        
        # Open the PortList Text File
        with open(portTextFile, 'r') as infile:
            
            # Process EachLine
            for nextLine in infile:
                
                lineList = nextLine.split()
                # Make sure we have a valid input line
                
                if len(lineList) >= 3:
                    # Split the line into parts
                    
                    # lineList[0] == PortType  (TCP or UDP)
                    # lineList[1] == PortNumber
                    
                    # Determine how many parts we have after type and port
                    
                    #portDescList = lineList[2:]
                    portDesc = ' '.join(lineList[2:])
    
                    # Now create a dictionary entry
                    # key = Port,Type
                    # Value = Description
                    
                    self.portDictionary[(lineList[1], lineList[0])] = portDesc
                else:
                    # Skip this line
                    continue
                
    def Lookup(self, portNumber, portType):
        
        try:
            portDesc = self.portDictionary[str(portNumber),portType]
        except:
            portDesc = "Unknown"
            
        return portDesc
        
# End PortsClass Definition


#  
# Class: IPObservationDictionary
#
# Desc: Handles all methods and properties
#       relating to the IPOservations 
#
#

class IPObservationDictionary:

    # Constructor
    
    def __init__(self):
        
        #Attributes of the Object
        
        # Dictionary to Hold IP Observations
        self.Dictionary = {}    
        self.observationsLoaded  = False
        self.observationFileName = ""
        
        
        # Instantiate the PortsClass Object
        # Creates and object that can be used
        # to lookup port descriptions
        #
        
        self.portOB = PortsClass("PortList.txt")
   
    # Method to Add an observation
    
    def AddOb(self, key):
       
        # Obtain the current hour
        
        now = datetime.datetime.now()
        hour = now.hour

        # Check to see if key is already in the dictionary
        
        if key in self.Dictionary:
        
            # If yes, retrieve the current value
            curValue = self.Dictionary[key]
            
            # Increment the count for the current hour
            curValue[hour-1] = curValue[hour-1] + 1
            
            # Update the value associated with this key
            self.Dictionary[key] = curValue
        
        else:
            # if the key doesn't yet exist
            # Create one
            
            curValue = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            
            # Increment the count for the current hour
            curValue[hour-1] = curValue[hour-1] + 1
    
            self.Dictionary[key] = curValue

    # Method to retrieve an observation
    # If no observation found return None
    
    def GetOb(self,key):
        
        if key in self.Dictionary:
            curValue = self.Dictionary[key]
            return curValue
        else:
            return None
        
    # Print the Contents of the Dictionary
    
    def PrintOb(self):
        print >> OUT, "\nIP Observations"
        print >> OUT, "Unique Combinations:    ", str(len(self.Dictionary))
        print >> OUT 
        
        # print Heading

        print >> OUT, '                                                ',
        print >> OUT,"|-------------------------------------------  Hourly Observations  --------------------------------------------------|"
        print >> OUT,'%16s' % "Server",
        print >> OUT,'%16s' % "Client",
        print >> OUT,'%7s'  % "Port",
        print >> OUT,'%5s'  % "Type"
        print >> OUT,'------------------------------------------------------------------------------------------------------------------------------------------------------------------------'
        print >> OUT,'                                               ',
        for i in range(0, 24):
            print  >> OUT,' ',            
            print >> OUT,'%02d' % i,
        print >> OUT

        sorted = self.Dictionary.items()
        sorted.sort()
        
        # Print Contents
        for keys,values in sorted:        
            
            print >> OUT,'%16s' % keys[SERVER],
            print >> OUT,'%16s' % keys[CLIENT],
            print >> OUT,'%7s'  % str(keys[PORT]),
            print >> OUT,'%5s'  % keys[TYPE],
            
            for i in range(0, 24):
                print >> OUT, '%4s' % str(values[i]),
            
            print >> OUT
        
        print >> OUT, "\nEnd Print Observations\n"
        
    def Histogram(self, observations):
        """
        Histogram data to stdout
        """
        largest = max(observations)
        scale = 100. / largest
        for hr, datum in enumerate(observations):
            bar = "*" * int(datum * scale)
            if bar == "" and datum > 0:
                bar = "*"
                print >> OUT, "%02d: %s (%d)" % (hr, bar, datum)
            elif datum != 0:
                print >> OUT, "%02d: %s (%d)" % (hr, bar, datum)
            else: 
                print >> OUT, "%02d:" % hr
        print >> OUT, "\n"
        
    # 
    # PrintUniqueServer List
    #
    # Method to Print to Standard Out each Server IP
    # Options include: lookupHost and lookupCountry
    # If selected, they will perform the respective lookups
    # and report data received
    #
    
    def PrintServers(self):
        
        print >> OUT, "\nUnique Server List\n"
        print >> OUT, '--------------------------------------------------------------------------'
        
        # Create "set" of server IP addresses
        # from the Dictionary
        
        self.servers = set()
                
        for keys,values in self.Dictionary.items():     
            self.servers.add(keys[SERVER])
        
        # Convert Set to List and Sort 
        # This method will ensure unique sorted list
        
        serverList = list(self.servers)
        serverList.sort()
        
        # Process Each Server IP in the sorted list
        
        for serverIP in serverList:

            # if Country Lookup is selected
            # perform the lookup, else set Country to blank
            if COUNTRY_LOOKUP:
                countryName = GetCountry(serverIP)
            else:
                countryName = ""
                
            # Set a Try / Except Loop in case of network error.
            
            try:
                # if caller requested hostname lookup
                # perform the lookup, else set name to blank
                if HOST_LOOKUP:
                    hostName = socket.gethostbyaddr(serverIP)
                else:
                    hostName = ["", "", ""]
            except:
                hostName = ""
                pass
            
            # Print out formatted results
            print >> OUT,' %15s ' % serverIP, 
            print >> OUT,' %15s ' % countryName, 
            print >> OUT,' %60s ' % hostName[HOST_NAME]
            
            self.ports = set()
            
            for keys,values in self.Dictionary.items():  
                if keys[SERVER] == serverIP:
                    self.ports.add( (keys[PORT], keys[TYPE]) )
                    
            portList = list(self.ports)
            portList.sort()
            
            for port in portList:
                print >> OUT,' %27s ' % str(port[0]),
                print >> OUT,' %5s ' % port[1],
                print >> OUT,'%40s'  % self.portOB.Lookup(port[0],port[1])
            print >> OUT, '--------------------------------------------------------------------------'
            
        print >> OUT
        print >> OUT, "End Print Servers\n"        
        print >> OUT, "\n\n"
        
    # End PrintUniqueServer List

    # 
    # Print Detailed Server List
    #
    # Method to Print to Standard Out 
    # Unique Server / Client Interactions
    #
    
    def PrintServerDetails(self):
        
        # Create "set" of server IP addresses
        # from the Dictionary
        print >> OUT, "\nUnique Server Client Connection List\n"
        print >> OUT, '--------------------------------------------------------------------------'
        
        self.servers = set()
        
        for keys,values in self.Dictionary.items():     
            self.servers.add(keys[SERVER])
            # Convert Set to List and Sort 
            # This method will ensure unique sorted list
            
        # Now create a sorted list of unique servers
        serverList = list(self.servers)
        serverList.sort()
        
        # Now Iterate through the server list 
        # finding all the matching server connections
        # and provide connection details
        
        for serverIP in serverList:
            
            # if Country Lookup is selected
            # perform the lookup, else set Country to blank
            if COUNTRY_LOOKUP:
                countryName = GetCountry(serverIP)
            else:
                countryName = ""
                
            # Set a Try / Except Loop in case of network error.
            
            try:
                # if caller requested hostname lookup
                # perform the lookup, else set name to blank
                if HOST_LOOKUP:
                    hostName = socket.gethostbyaddr(serverIP)
                else:
                    hostName = ["", "", ""]
            except:
                hostName = ""
                continue
            
            # Print out formatted results
            print >> OUT,"\n============================================================"
            print >> OUT,"Server: ", 
            print >> OUT,' %15s ' % serverIP, 
            print >> OUT,' %15s ' % countryName, 
            print >> OUT,' %60s ' % hostName[HOST_NAME]
            print >> OUT,"============================================================"
            print >> OUT,'%16s' % "Client",
            print >> OUT,'%7s'  % "Port",
            print >> OUT,'%40s'  % "Port Description",
            print >> OUT,'%5s'  % "Type",
            print >> OUT        
            
            for keys,values in self.Dictionary.items():    
                
                # If server matches current
                # print out the details:
                
                if keys[SERVER] == serverIP:
                    print >> OUT,'%16s' % keys[CLIENT],
                    print >> OUT,'%7s'  % str(keys[PORT]),
                    print >> OUT,'%40s'  % self.portOB.Lookup(keys[PORT],keys[TYPE]),
                    print >> OUT,'%5s'  % keys[TYPE]
        print >> OUT
        print >> OUT, "End Print Server Details\n"        
        
    # End PrintUniqueServer List

    # 
    # Print Capture Histogram
    #
    # Method to Print a  
    # Histogram for each Entry
    #
            
    def PrintHistogram(self):
    
        # Create "set" of server IP addresses
        # from the Dictionary
        
        print >> OUT,"\nHourly Histogram\n"
        
        self.servers = set()
        
        for keys,values in self.Dictionary.items():     
            self.servers.add(keys[SERVER])
            # Convert Set to List and Sort 
            # This method will ensure unique sorted list
            
        # Now create a sorted list of unique servers
        serverList = list(self.servers)
        serverList.sort()
        
        # Now Iterate through the server list 
        # finding all the matching server connections
        # and provide connection details
        
        for serverIP in serverList:
            
            # if Country Lookup is selected
            # perform the lookup, else set Country to blank
            
            if COUNTRY_LOOKUP:
                countryName = GetCountry(serverIP)
            else:
                countryName = ""
                
            # Set a Try / Except Loop in case of network error.
            
            try:
                # if caller requested hostname lookup
                # perform the lookup, else set name to blank
                if HOST_LOOKUP:
                    hostName = socket.gethostbyaddr(serverIP)
                else:
                    hostName = ["", "", ""]
            except:
                hostName = ["", "", ""]
                continue
            
            # Print out formatted results
            print >> OUT,"\n============================================================"
            print >> OUT,"Server: ", 
            print >> OUT,' %15s ' % serverIP, 
            print >> OUT,' %15s ' % countryName, 
            print >> OUT,' %60s ' % hostName[HOST_NAME]
            print >> OUT,"============================================================"      
            
            for keys,values in self.Dictionary.items():    
                
                # If server matches current
                # print out the histogram
                
                if keys[SERVER] == serverIP:
                    if keys[SERVER] == serverIP:
                        print >> OUT,'%16s' % "Client",
                        print >> OUT,'%7s'  % "Port",
                        print >> OUT,'%40s' % "Port Description",
                        print >> OUT,'%5s'  % "Type",
                        print >> OUT                             
                        print >> OUT,'%16s' % keys[CLIENT],
                        print >> OUT,'%7s'  % str(keys[PORT]),
                        print >> OUT,'%40s' % self.portOB.Lookup(keys[PORT],keys[TYPE]),
                        print >> OUT,'%5s'  % keys[TYPE]   
                        print >> OUT
                        print >> OUT,"HOUR"
                        self.Histogram(values)
    
        print >> OUT
        print >> OUT, "End Print Histogram\n"
        
# End Histogram Output

                    
    # 
    # Print Unique Client List
    #
    # Method to Print Out each Client IP
    # Options include: lookupHost and lookupCountry
    # If selected, they will perform the respective lookups
    # and report data received
    
    def PrintClients(self):
        
        print >> OUT,"\nUnique Client List\n"
        
        self.clients = set()
        for keys,values in self.Dictionary.items():     
            self.clients.add(keys[1])
        
        clientList = list(self.clients)
        clientList.sort()

        # Process Each Server IP in the sorted list
        
        for clientIP in clientList:

            # if Country Lookup is selected
            # perform the lookup, else set Country to blank
            if COUNTRY_LOOKUP:
                countryName = GetCountry(clientIP)
            else:
                countryName = ""
                
            # Set a Try / Except Loop in case of network error.
            
            try:
                # if caller requested hostname lookup
                # perform the lookup, else set name to blank
                if HOST_LOOKUP:
                    hostName = socket.gethostbyaddr(clientIP)
                else:
                    hostName = ["","",""]
            except:
                hostName = ["","",""]
                pass
            
            # Print out formatted results
            
            print >> OUT,' %15s ' % clientIP, 
            print >> OUT,' %15s ' % countryName, 
            print >> OUT,' %60s ' % hostName[HOST_NAME]
        
        print >> OUT, "\nEnd Print Client List\n"
        
     # End PrintUniqueClient List
     
     
    # Save the Current Observation Dictionary
    # to the specified file
    
    def SaveOb(self, fileName):
        
        with open(fileName, 'wb') as fp:
            pickle.dump(self.Dictionary, fp)             
        
    # Load in and Observation Dictionary
    # from the specified file
    
    def LoadOb(self, fileName):
        try:
            with open(fileName, 'rb') as fp:
                self.Dictionary = pickle.loads(fp.read())
                self.observationFileName = fileName
                self.observationsLoaded  = True  
        except:
            print "Loading Observations - Failed"
            self.observationsLoaded  = False
            self.observationFileName = ""
    
    def PrintIPAnalysisMenu(self):
        
        print "========== P2NMAP Analysis Menu ==========\n"
        
        if self.observationsLoaded:
            print "Current Observation File: ", self.observationFileName
            print

        print "[L]    Load Observation File for Analysis" 
        
        if self.observationsLoaded:
            if PRINT_STDOUT:
                print "[O]    Direct Output to File   (Current = Stdout)"
            else:
                print "[O]    Direct Output to Stdout (Current = results.txt)"
                
            if HOST_LOOKUP:
                print "[H]    Turn Off Host Lookup    (Current = Host Lookup On)"
            else:
                print "[H]    Turn On Host Lookup     (Current = Host Lookup Off)"
            
            if COUNTRY_LOOKUP:
                print "[C]    Turn Off Country Lookup (Current = Country Lookup On)"
            else:
                print "[C]    Turn On Country Lookup  (Current = Country Lookup Off)"    
            
            print "============================================================="    
            print "[1]    Print Observations      (ALL)"
            print "[2]    Print Servers           (Unique)"
            print "[3]    Print Clients           (Unique)"
            print "[4]    Print Connections       (Unique by Server)"
            print "[5]    Print Histogram"
            print
        print "[X]    Exit P2NMAP Analysis"
        print    

    # Destructor Delete the Object
    
    def __del__(self):
        if VERBOSE:
            print >> OUT,"Closed"
                   
# End IPObservationClass ====================================

#===================================
# Main Program Starts Here
#===================================

if __name__ == '__main__':
    
    # Set VERBOSE to True    
    VERBOSE = True
    
    # Create an ip observation object
    
    ipOB = IPObservationDictionary() 
    
    while True:
        
        ipOB.PrintIPAnalysisMenu()
        
        menuSelection = raw_input("Enter Selection: ").upper()
        
        if menuSelection == 'L':
            fileName = raw_input("Enter IP Capture File: ")
            ipOB.LoadOb(fileName)
            print
            
        elif menuSelection == 'O':
            if PRINT_STDOUT:
                PRINT_STDOUT = False
                OUT = open("results.txt", 'w+')
            else:
                PRINT_STDOUT = True  
                OUT.close()
                OUT = sys.stdout
        elif menuSelection == 'H':
            if HOST_LOOKUP:
                HOST_LOOKUP = False
            else:
                HOST_LOOKUP = True   
                
        elif menuSelection == 'C':
            if COUNTRY_LOOKUP:
                COUNTRY_LOOKUP = False
            else:
                COUNTRY_LOOKUP = True                 
        elif menuSelection == '1':
            ipOB.PrintOb()
        elif menuSelection == '2':
            ipOB.PrintServers()
        elif menuSelection == '3':
            ipOB.PrintClients()
        elif menuSelection == '4':
            ipOB.PrintServerDetails()    
        elif menuSelection == '5':
            ipOB.PrintHistogram()            
        elif menuSelection == 'X':
            break
        else:
            print "Entry not recognized"
            continue
        
        OUT.flush()
        
print >> OUT, "End P2NMAP"

