import pickle
import driverlib

from immlib import *

def main( args ):

    ioctl_list  = []
    device_list = []

    dbg    = Debugger()
    driver = driverlib.Driver()

    # Grab the list of IOCTL codes and device names
    ioctl_list  = driver.getIOCTLCodes()
    if not len(ioctl_list):
        return "[*] ERROR! Couldn't find any IOCTL codes."
    
    device_list = driver.getDeviceNames()
    if not len(device_list):
        return "[*] ERROR! Couldn't find any device names."
    
    # Now create a keyed dictionary and pickle it to a file
    master_list = {}
    master_list["ioctl_list"]  = ioctl_list
    master_list["device_list"] = device_list

    fd = open( args[0], "wb")
    pickle.dump( master_list, fd )
    fd.close()
    

    return "[*] SUCCESS! Saved IOCTL codes and device names to %s" % args[0]
