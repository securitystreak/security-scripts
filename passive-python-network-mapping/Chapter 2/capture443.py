# Python Script to Map Activity on a single port
# Running on Linux

# Import Standard Library Modules

import socket           # network interface library used for raw sockets
import os               # operating system functions i.e. file I/o
import sys              # system level functions i.e. exit()
from struct import *    # Handle Strings as Binary Data 

# Constants

PROTOCOL_TCP = 6        # TCP Protocol for IP Layer

# PacketExtractor
#
# Purpose: Extracts fields from the IP and TCP Header
#
# Input:   packet:     buffer from socket.recvfrom() method
# Output:  list:       serverIP, clientIP, serverPort
#

def PacketExtractor(packet):

    #Strip off the first 20 characters for the ip header
    stripPacket = packet[0:20]
     
    #now unpack them
    ipHeaderTuple = unpack('!BBHHHBBH4s4s' , stripPacket)
        
    # unpack returns a tuple, for illustration I will extract
    # each individual values
                                           # Field Contents
    verLen       = ipHeaderTuple[0]        # Field 0: Version and Length
    TOS          = ipHeaderTuple[1]        # Field 1: Type of Service                                      
    packetLength = ipHeaderTuple[2]        # Field 2: Packet Length
    packetID     = ipHeaderTuple[3]        # Field 3: Identification  
    flagFrag     = ipHeaderTuple[4]        # Field 4: Flags and Fragment Offset
    RES          = (flagFrag >> 15) & 0x01 # Reserved
    DF           = (flagFrag >> 14) & 0x01 # Don't Fragment
    MF           = (flagFrag >> 13) & 0x01 # More Fragments
    timeToLive   = ipHeaderTuple[5]        # Field 5: Time to Live (TTL)
    protocol     = ipHeaderTuple[6]        # Field 6: Protocol Number 
    checkSum     = ipHeaderTuple[7]        # Field 7: Header Checksum
    sourceIP     = ipHeaderTuple[8]        # Field 8: Source IP
    destIP       = ipHeaderTuple[9]        # Field 9: Destination IP    
    
    # Calculate / Convert extracted values
    
    version      = verLen >> 4             # Upper Nibble is the version Number
    length       = verLen & 0x0F           # Lower Nibble represents the size
    ipHdrLength  = length * 4              # Calculate the header length in bytes
    
    # covert the source and destination address to typical dotted notation strings
       
    sourceAddress      = socket.inet_ntoa(sourceIP);
    destinationAddress = socket.inet_ntoa(destIP);
    
    if protocol == PROTOCOL_TCP:
        
        stripTCPHeader = packet[ipHdrLength:ipHdrLength+20]
             
        # unpack returns a tuple, for illustration I will extract
        # each individual values using the unpack() function

        tcpHeaderBuffer = unpack('!HHLLBBHHH' , stripTCPHeader)
         
        sourcePort             = tcpHeaderBuffer[0]
        destinationPort        = tcpHeaderBuffer[1]
        sequenceNumber         = tcpHeaderBuffer[2]
        acknowledgement        = tcpHeaderBuffer[3]
        dataOffsetandReserve   = tcpHeaderBuffer[4]
        tcpHeaderLength        = (dataOffsetandReserve >> 4) * 4
        flags                  = tcpHeaderBuffer[5]
        FIN                    = flags & 0x01
        SYN                    = (flags >> 1) & 0x01
        RST                    = (flags >> 2) & 0x01
        PSH                    = (flags >> 3) & 0x01
        ACK                    = (flags >> 4) & 0x01
        URG                    = (flags >> 5) & 0x01
        ECE                    = (flags >> 6) & 0x01
        CWR                    = (flags >> 7) & 0x01
        windowSize             = tcpHeaderBuffer[6]
        tcpChecksum            = tcpHeaderBuffer[7]
        urgentPointer          = tcpHeaderBuffer[8]

        if sourcePort < 1024:
            serverIP   = sourceAddress
            clientIP   = destinationAddress
            serverPort = sourcePort
        elif destinationPort < 1024:
            serverIP   = destinationAddress
            clientIP   = sourceAddress
            serverPort = destinationPort
        else:
            serverIP   = "Filter"
            clientIP   = "Filter"
            serverPort = "Filter"
            
        return([serverIP, clientIP, serverPort], [SYN, serverIP, TOS, timeToLive, DF, windowSize])
    else:
        return(["Filter", "Filter", "Filter"], [NULL, Null, Null, Null])
    
        
# ------------ MAIN SCRIPT STARTS HERE -----------------

if __name__ == '__main__':


    # Note script must be run in superuser mode
    # i.e. sudo python ..
    
    # Enable Promiscious Mode on the NIC
    # Make a system call 
    # Note: Linux Based
    
    ret =  os.system("ifconfig eth0 promisc")
    
    # If successful, then continue
    if ret == 0:
        
        print "eth0 configured in promiscous mode"
        
        # create a new socket using the python socket module
        # AF_INET     : Address Family Internet
        # SOCK_RAW    : A raw protocol at the network layer
        # IPPROTO_TCP : Specifies the socket transport layer is TCP
        
        # Attempt to open the socket
        try:
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # if successful post the result
            print "Raw Socket Open"
        except:
            # if socket  fails
            print "Raw Socket Open Failed"
            sys.exit()
        
        # create a list to hold the results from the packet capture
        # I'm only interested in storing the Server IP, Client IP, Server Port
        # for this example.  Note we will be making and educated guess as to
        # differentiate Server vs. Client
        
        ipObservations = []    
        osObservations = []
    
        # Capture a maximum of 500 observations
        maxObservations = 500
        
        # Port filter set to port 443
        # TCP Port 443 is defined as the http protocol over TLS/SSL
        
        portValue = 443
        
        try:
            
            while maxObservations > 0:
                
                # attempt recieve (this call is synchronous, thus it will wait)
                recvBuffer, addr = mySocket.recvfrom(255)
                
                # decode the received packet
                # call the local packet extract function above
                
                content, fingerPrint = PacketExtractor(recvBuffer)
    
                if content[0] != "Filter":
                    # append the results to our list
                    # if it matches our port
                    if content[2] == portValue:
                        ipObservations.append(content)
                        maxObservations = maxObservations - 1
                        # if the SYN flag is set then
                        # record the fingerprint data in osObservations
                        if fingerPrint[0] == 1:
                            osObservations.append([fingerPrint[1], \
                                                  fingerPrint[2],  \
                                                  fingerPrint[3],  \
                                                  fingerPrint[4],  \
                                                  fingerPrint[5]])
                    else:
                        # Not our port
                        continue
                else:
                    # Not a valid packet
                    continue
    
        except:
            print "socket failure"
            exit()
    
        # Capture Complete
        # Disable Promiscous Mode
        # using Linux system call
        ret =  os.system("ifconfig eth0 -promisc")
        
        # Close the Raw Socket
        mySocket.close()
        
        # Create unique sorted list
        # Next we convert the list into a set to eliminate
        # any duplicate entries
        # then we convert the set back into a list for sorting

        uniqueSrc = set(map(tuple, ipObservations))
        finalList = list(uniqueSrc)
        finalList.sort()
        
        uniqueFingerprints = set(map(tuple, osObservations))
        finalFingerPrintList = list(uniqueFingerprints)
        finalFingerPrintList.sort()
        
        
        # Print out the unique combinations
        print "Unique Packets"
        for packet in finalList:
            print packet
        print "Unique Fingerprints"
        for osFinger in finalFingerPrintList:
            print osFinger
    else:
        print 'Promiscious Mode not Set'
