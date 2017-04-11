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
# Process .pcap files 
# Create .ipdict and .osdict result files 
#         suitable for analysis with P2NMAP-Analyze
#                               and  P2NMAP-OSEstimator

# import support functions

import argparse                 # Python Standard Library Parsing Module
import os                       # Python Standard Library OS module
import sys                      # Python Standard Library SYS Module
import socket                   # Python Standard Library socket module
import time                     # Python Standard Library time module
import datetime                 # Python Standard Library datetime module
import pickle                   # Python Standard Library pickling module

import dpkt                     # 3rd Party Packet Parsing Module
                                # pip install dptk    to intall the module
from dpkt.udp import UDP        # Import specific objects from DPKT for convience
from dpkt.tcp import TCP        # 

# CONSTANTS

HOUR_INDEX = 3                  # Index of the Hour value in the Time Structure

#
# Name: ValDirWrite
#
# Desc: Function that will validate a directory path as 
#       existing and writable.  Used for argument validation only
#
# Input: a directory path string
#  
# Actions: 
#              if valid will return the Directory String
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#

def ValDirWrite(theDir):

    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')

    # Validate the path is writable
    if os.access(theDir, os.W_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not writable')

#End ValDirWrite ===================================


#
# Name: ValidateFileRead Function
#
# Desc: Function that will validate that a file exists and is readable
#
# Input: A file name with full path
#  
# Actions: 
#              if valid will return path
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#

def ValFileRead(theFile):

    # Validate the path is a valid
    if not os.path.exists(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    # Validate the path is readable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')

#End ValidateFileRead ===================================



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
        
        self.Dictionary = {}            # Dictionary to Hold IP Observations
   
    # Method to Add an observation
    
    def AddOb(self, key, hour):

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

    # Print the Contents of the Dictionary
    
    def PrintOb(self):
        print "\nIP Observations"
        print "Unique Combinations:    ", str(len(self.Dictionary))
        print
        
        # Print Heading

        print '                                                ',
        print "|-------------------------------------------  Hourly Observations  --------------------------------------------------|"
        print '%16s' % "Server",
        print '%16s' % "Client",
        print '%7s'  % "Port",
        print '%5s'  % "Type",
        
        for i in range(0, 24):
            print  ' ',            
            print '%02d' % i,
        print
        
        sorted = self.Dictionary.items()
        sorted.sort()
        
        # Print Contents
        for keys,values in sorted:        
            
            print '%16s' % keys[0],
            print '%16s' % keys[1],
            print '%7s'  % str(keys[2]),
            print '%5s'  % keys[3],
            
            for i in range(0, 24):
                print '%4s' % str(values[i]),
            print
            
    # Save the Current Observation Dictionary
    # to the specified file
    
    def SaveOb(self, fileName):
        
        with open(fileName, 'wb') as fp:
            pickle.dump(self.Dictionary, fp)             
                
    # Destructor Delete the Object
    
    def __del__(self):
        if VERBOSE:
            print "Closed"
        
# End IPObservationClass ====================================

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
   
    # Method to Add an observation
    
    def AddOb(self, key, hour):

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
        
        print "\nOS Observations"
        print "Unique Combinations:    ", str(len(self.Dictionary))
        print
        
        
        # Print Heading
        print '                                          ',
        print "|-------------------------------------------  Hourly Observations  ---------------------------------------------------|"
        
        print '%16s' % "Server",
        print '%4s'  % "TOS",
        print '%4s'  % "TTL",
        print '%6s'  % "DF",
        print '%7s'  % "Window",
        
        for i in range(0, 24):
            print ' ',            
            print '%02d' % i,
        print "\n-----------------------------------------------------------------------------------------------------------------------------------------------------------------"
        
        sorted = self.Dictionary.items()
        sorted.sort()
        
        # Print Contents
        for keys,values in sorted:
            print '%16s' % keys[0],
            print '%4s'  % str(keys[1]),
            print '%4s'  % str(keys[2]),
            print '%6s'  % str(keys[3]),
            print '%7s'  % str(keys[4]),
            
            for i in range(0, 24):
                print '%4s' % str(values[i]),
            print 
            
    # End Print OS Observations

          
    # Save the Current Observation Dictionary
    # to the specified file
    
    def SaveOb(self, fileName):
        
        with open(fileName, 'wb') as fp:
            pickle.dump(self.Dictionary, fp)             
        
    # Destructor Delete the Object
    
    def __del__(self):
        if VERBOSE:
            print "Closed"
        
# End OSObservationClass ====================================

#===================================
#
# Main Program Starts Here
#===================================

if __name__ == '__main__':

    # Setup Argument Parser Object

    parser = argparse.ArgumentParser('P2NAMP PCAP Extractor')
       
    parser.add_argument('-v', '--verbose', help="Provide Progress Messages", action='store_true')
    parser.add_argument('-o', '--outPath', type= ValDirWrite, required=True, help="Output Directory")         
    parser.add_argument('-i', '--inFile' , type= ValFileRead, required=True, help="PCAP input File - Full Path")         
    
    #process the command arguments
    
    cmdArgs = parser.parse_args()  
    
    # convert arguments to simple local variables
    
    VERBOSE    = cmdArgs.verbose
    inFile     = cmdArgs.inFile
    outPath    = cmdArgs.outPath
       
    if VERBOSE:
        print "Packet Parsing Algorithm, version 1.0"
        print
        
        print "Opening Capture File: "+ inFile
        print
            
    
    # Create IP observation dictionary object   
    ipOB = IPObservationDictionary() 
    osOB = OSObservationDictionary()
    
    # Loop through all the packets found in the pcap file
    # Obtain the timestamp and packet data
    
    if VERBOSE:
        print "Processing PCAP, please wait ...\n"
        
    # Use dpkt and setup a pcapReader Object
    try:
        # Create pcapReader Object
        pcapReader = dpkt.pcap.Reader(file(inFile, "rb"))
    except:
        # Error Reading pcap
        print "Error importing: ", infile
        quit()
    
    # Using the pcapReader Object process the
    # the contents of the selected pcap file
    
    # each interation through the loop will return
    # 1) packet timestamp
    # 2) packet raw data
    
    for timeStamp, pckData in pcapReader:
        
        # Next I retrieve the etherNet packet contents
        # and verify that it is an ethernet packet
        
        etherNet = dpkt.ethernet.Ethernet(pckData)
        
        # Verify that this ethernet packet carries an IP Packet
        
        if etherNet.type == dpkt.ethernet.ETH_TYPE_IP: 
                            
            # get the ip data and extract the source and destination ip addresses
            # use the socket module to convert them to dot notational form
    
            # Decode the source and destination IP Address
            ip = etherNet.data
            sourceAddress      = socket.inet_ntoa(ip.src)
            destinationAddress = socket.inet_ntoa(ip.dst)
            
            # Check Packet Type (either TCP or UDP and process accordingly)
    
            if type(ip.data) == TCP :
                
                # Extract and Decode the Ports in use
                tcp = ip.data
                
                # Obtain Data for OS Fingerprinting
                
                # SYN Flag
                SYN = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                
                # DF Flag
                DF = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
                
                # Window Size
                WINDOW_SIZE = tcp.win
                
                # Time to Live and Type of Service values
                TTL = ip.ttl
                TOS = ip.tos
                
                # Now obtain the Source and Destination Port
                sourcePort      = tcp.sport
                destinationPort = tcp.dport
                
                if sourcePort <= 1024:              # Assume server IP is server
                    serverIP   = sourceAddress
                    clientIP   = destinationAddress
                    serverPort = sourcePort
                    status = True
                elif destinationPort <= 1024:       # Assume destination IP is server
                    serverIP   = destinationAddress
                    clientIP   = sourceAddress
                    serverPort = destinationPort
                    status = True
                elif sourcePort <= destinationPort: # Assume server IP is server
                    serverIP   = sourceAddress
                    clientIP   = destinationAddress
                    serverPort = sourcePort
                    status = True
                elif sourcePort > destinationPort:  # Assume distinatin IP is server
                    serverIP   = destinationAddress
                    clientIP   = sourceAddress
                    serverPort = destinationPort
                    status = True         
                else:                               # Should never get here
                    serverIP   = "FILTER"
                    clientIP   = "FILTER"
                    serverPort = "FILTER"
                    status = False
                
                # Convert the timestamp (epoch value)
                # into a time structure
                timeStruct = time.gmtime(timeStamp)
                
                # extract the hour the packet was captured
                theHour = timeStruct[HOUR_INDEX]
                
                if status:
                    # Add a new IP observation and the hour
                    ipOB.AddOb((serverIP, clientIP, serverPort, "TCP"), theHour)
                    
                    # If SYN is set also add a new OS Observation 
                    if SYN:
                        osOB.AddOb( (serverIP, TOS, TTL, DF, WINDOW_SIZE), theHour)
                        
                                
            elif type(ip.data) == UDP :
                
                # Extract and Decode the Ports in use
                udp = ip.data
                sourcePort      = udp.sport
                destinationPort = udp.dport
                
                if sourcePort <= 1024:              # Assume server IP is server
                    serverIP   = sourceAddress
                    clientIP   = destinationAddress
                    serverPort = sourcePort
                    status = True
                elif destinationPort <= 1024:       # Assume destination IP is server
                    serverIP   = destinationAddress
                    clientIP   = sourceAddress
                    serverPort = destinationPort
                    status = True
                elif sourcePort <= destinationPort: # Assume server IP is server
                    serverIP   = sourceAddress
                    clientIP   = destinationAddress
                    serverPort = sourcePort
                    status = True
                elif sourcePort > destinationPort:  # Assume distinatin IP is server
                    serverIP   = destinationAddress
                    clientIP   = sourceAddress
                    serverPort = destinationPort
                    status = True         
                else:                               # Should never get here
                    serverIP   = "FILTER"
                    clientIP   = "FILTER"
                    serverPort = "FILTER"
                    status = False

                # Convert the timestamp (epoch value)
                # into a time structure
                
                timeStruct = time.gmtime(timeStamp)
                theHour = timeStruct[3]
                
                if status:
                    # Add a new observation and the hour
                    ipOB.AddOb((serverIP, clientIP, serverPort, "UDP"), theHour)  
            else:
                # Skip the Packet NOT TCP or UDP
                continue
        else:
            # skip this packet NOT Ethernet Type
            continue
    
    # Once all packets are processed            
    # Print out Results
    
    if VERBOSE:
        
        ipOB.PrintOb()    
        osOB.PrintOb()
        
        print "\nSaving Observations ext: .ipDict and .osDict"
    
    # Save observations in our compatible format
    
    ipOutFile = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+".ipDict"
    ipOutput  = os.path.join(outPath, ipOutFile)
    
    osOutFile = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+".osDict"
    osOutput  = os.path.join(outPath, osOutFile)
    
    ipOB.SaveOb(ipOutput)
    osOB.SaveOb(osOutput)
    
    print 'Processing Complete'