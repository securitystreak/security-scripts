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

e.g. usage

python memScanner.py -f memAll.bin -c -q
                      |             |  |_ Optional Argument to print NO standard out messages
                      |             |  
                      |             |_ Optional Argument to create csv files for each category
                      |
                      |_ Mandatory Argument Filename to Process
                      

Overview:

Script digests virtually any file Text or Binary (based on available memory) and attempts
to extract key data (possibly evidence) from the file.  Current Support Includes:

- e-mail
- urls
- Social Security Numbers
- strong passwords (strings contain 6-12 continuous characters)
                   (with at least 1 upper case, 1 lower case and 1 number)
- Credit Card Numbers (AMEX, MC, Visa, Discover)
- U.S. Phone Numbers
- U.S. Postal Codes

'''

import argparse     # Python Standard Library to Parse Command Line
import pfDiscover   # Python Foreniscs Discover Module
import time         # Python Standard Library Time Module

#
# ------ MAIN SCRIPT STARTS HERE -----------------
#

if __name__ == '__main__':
    
    # Setup Argument Parser
       
    parser = argparse.ArgumentParser('Python Memory Image Scanner v .95 Beta May 2016')
    
    parser.add_argument('-f',  '--filePath', required=True, help='path and filename of object to be examined')
    parser.add_argument('-c',  '--csv',                     help='create csv file results', action='store_true')
    parser.add_argument('-q',  '--quiet',                   help='run silent - no standard output results', action='store_true')
      
    # Process the Arguments
    theArgs = parser.parse_args()     

    # Get the filename to process
    path = theArgs.filePath
    
    # Process the Optional Arguments
    if theArgs.csv:
        CSV = True
    else:
        CSV = False
        
    if theArgs.quiet:
        QUIET = True
    else:
        QUIET = False
        
    if not QUIET:
        print "Memory Image Scanner v 0.95 Beta May 2016\n"
            
    #Call the FileExaminer class with the filename provided
    
    FEobj = pfDiscover.FileExaminer(path) 
       
    # Verify File is available and ready
    if FEobj.lastError == "OK":
    
        if not QUIET:
            print "File Processed: ", FEobj.path
            print "File  Size:     ", "{:,}".format(FEobj.fileSize), "bytes"
            print "MAC  Times:     ", FEobj.macTimes
            
        # Scan the file
        
        startTime = time.time()
        
        result = FEobj.scanMem(QUIET)
        
        endTime = time.time()

        elapsedTime = endTime - startTime

        print "Scan Completed"
        print "Elapsed Time: ", elapsedTime, "Seconds"
        
        # If this produced results
        if result:
            
            # Print to the Screen if not in Quiet Mode
            if not QUIET:

                FEobj.printEmails()
                FEobj.printURLs()
                FEobj.printSSNs()  
                FEobj.printPWs()   
                FEobj.printCCs()   
                FEobj.printUSPHs()     
                FEobj.printZIPs()   
                
            # Generate CSV files -c Argument provided
            if CSV:

                FEobj.csvEmails()
                FEobj.csvURLs()
                FEobj.csvSSNs()  
                FEobj.csvPWs()   
                FEobj.csvCCs()  
                FEobj.csvUSPHs()  
                FEobj.csvZIPs()                  
        else:
            print FEobj.lastError
                    
        #Clean up the object used for processing
        del FEobj        
        
    else:
        print "Last Error: ", FEobj.lastError
        
