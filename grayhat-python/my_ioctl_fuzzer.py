import pickle
import sys
import random

from ctypes import *

kernel32 = windll.kernel32

# Defines for Win32 API Calls
GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
OPEN_EXISTING   = 0x3

# Open the pickle and retrieve the dictionary 
fd          = open(sys.argv[1], "rb")
master_list = pickle.load(fd)
ioctl_list  = master_list["ioctl_list"]
device_list = master_list["device_list"]
fd.close()

# Now test that we can retrieve valid handles to all
# device names, any that don't pass we remove from our test cases
valid_devices = []


for device_name in device_list:

    # Make sure the device is accessed properly
    device_file = u"\\\\.\\%s" % device_name.split("\\")[::-1][0]

    print "[*] Testing for device: %s" % device_file

    driver_handle = kernel32.CreateFileW(device_file,GENERIC_READ|
                             GENERIC_WRITE,0,None,OPEN_EXISTING,0,None)

    if driver_handle:
        
        print "[*] Success! %s is a valid device!"

        if device_file not in valid_devices:
            valid_devices.append( device_file )
        
        kernel32.CloseHandle( driver_handle )
    else:
        print "[*] Failed! %s NOT a valid device."

if not len(valid_devices):
    print "[*] No valid devices found. Exiting..."
    sys.exit(0)

# Now let's begin feeding the driver test cases until we can't bear it anymore!
# CTRL-C to exit the loop and stop fuzzing
while 1:

    # Open the log file first
    fd = open("my_ioctl_fuzzer.log","a")

    # Pick a random device name
    current_device = valid_devices[ random.randint(0, len(valid_devices)-1 ) ]
    fd.write("[*] Fuzzing: %s" % current_device)
    
    # Pick a random IOCTL code
    current_ioctl  = ioctl_list[ random.randint(0, len(ioctl_list)-1)]
    fd.write("[*] With IOCTL: 0x%08x" % current_ioctl)

    # Choose a random length
    current_length = random.randint(0, 10000) y
    fd.write("[*] Buffer length: %d" % current_length)

    # Let's test with a buffer of repeating A's
    # Feel free to create your own test cases here
    in_buffer      = "A" * current_length

    # Give the IOCTL run an out_buffer
    out_buf        = (c_char * current_length)()
    bytes_returned = c_ulong(current_length)

    # Obtain a handle
    driver_handle = kernel32.CreateFileW(device_file, GENERIC_READ| 
                             GENERIC_WRITE,0,None,OPEN_EXISTING,0,None)

    fd.write("!!FUZZ!!")
    # Run the test case
    kernel32.DeviceIoControl( driver_handle, current_ioctl, in_buffer, 
                              current_length, byref(out_buf), 
                              current_length, byref(bytes_returned), 
                              None )

    fd.write( "[*] Test case finished. %d bytes returned.\n" % bytes_returned.value )
    
    # Close the handle and carry on!
    kernel32.CloseHandle( driver_handle )
    fd.close()