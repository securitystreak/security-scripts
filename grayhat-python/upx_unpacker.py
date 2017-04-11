from ctypes import *

import sys

# You must set your path to pyemu
sys.path.append("C:\\PyEmu")
sys.path.append("C:\\PyEmu\\lib")

from PyEmu import PEPyEmu

'''
HMODULE WINAPI LoadLibrary(
  __in  LPCTSTR lpFileName
);
'''
def loadlibrary(name, address):

    # Retrieve the DLL name 
    dllname   = emu.get_memory_string(emu.get_memory(emu.get_register("ESP") + 4))
    
    # Make a real call to LoadLibrary and return the handle
    dllhandle = windll.kernel32.LoadLibraryA(dllname)
    emu.set_register("EAX", dllhandle)
    
    # Reset the stack and return from the handler
    return_address = emu.get_memory(emu.get_register("ESP"))
    emu.set_register("ESP", emu.get_register("ESP") + 8)
    emu.set_register("EIP", return_address)
    
    return True
    
'''
FARPROC WINAPI GetProcAddress(
  __in  HMODULE hModule,
  __in  LPCSTR lpProcName
);
'''
def getprocaddress(name, address):

    # Get both arguments, which are a handle and the procedure name
    handle    = emu.get_memory(emu.get_register("ESP") + 4)
    proc_name = emu.get_memory(emu.get_register("ESP") + 8)
    
    # lpProcName can be a name or ordinal, if top word is null its an ordinal
    if (proc_name >> 16):
        procname = emu.get_memory_string(emu.get_memory(emu.get_register("ESP") + 8))
    else:
        procname = arg2
    
    # Add the procedure to the emulator
    emu.os.add_library(handle, procname)
    import_address = emu.os.get_library_address(procname)
    
    # Return the import address
    emu.set_register("EAX", import_address)
    
    # Reset the stack and return from our handler
    return_address = emu.get_memory(emu.get_register("ESP"))
    emu.set_register("ESP", emu.get_register("ESP") + 8)
    emu.set_register("EIP", return_address)

    return True

'''
BOOL WINAPI VirtualProtect(
  __in   LPVOID lpAddress,
  __in   SIZE_T dwSize,
  __in   DWORD flNewProtect,
  __out  PDWORD lpflOldProtect
);
'''
def virtualprotect(name, address):

    # Just return TRUE
    emu.set_register("EAX", 1)
    
    # Reset the stack and return from our handler
    return_address = emu.get_memory(emu.get_register("ESP"))
    emu.set_register("ESP", emu.get_register("ESP") + 16)
    emu.set_register("EIP", return_address)

    return True


# When the unpacking routine is finished, handle the JMP to the OEP
def jmp_handler(emu, mnemonic, eip, op1, op2, op3):
    
    # The UPX1 section	
    if eip < emu.sections["UPX1"]["base"]:
        print "[*] We are jumping out of the unpacking routine."
        print "[*] OEP = 0x%08x" % eip

	# Dump the unpacked binary to disk
        dump_unpacked(emu)
        
        # We can stop emulating now
        emu.emulating = False
        
        return True

# Dump out our newly unpacked binary        
def dump_unpacked(emu):

    global outputfile
    
    fh = open(outputfile, 'wb')

    print "[*] Dumping UPX0 Section"
    base   = emu.sections["UPX0"]["base"]
    length = emu.sections["UPX0"]["vsize"]
    print "[*] Base: 0x%08x  Vsize: %08x" % (base, length)

    for x in range(length):
        fh.write("%c" % emu.get_memory(base + x, 1))
    
    print "[*] Dumping UPX1 Section"
    base   = emu.sections["UPX1"]["base"]
    length = emu.sections["UPX1"]["vsize"]
    print "[*] Base: 0x%08x  Vsize: %08x" % (base, length)
    
    for x in range(length):
        fh.write("%c" % emu.get_memory(base + x, 1))
    
    print "[*] Finished."
    

# Commandline arguments
exename    = sys.argv[1]
outputfile = sys.argv[2]

# Instantiate our emulator object
emu = PEPyEmu()

if exename:
    
    # Load the binary into PyEmu
    if not emu.load(exename):
        print "[!] Problem loading %s" % exename
        sys.exit(2)
else:
    print "[!] Blank filename specified"
    sys.exit(3)


# Set our library handlers    
emu.set_library_handler("LoadLibraryA",   loadlibrary)
emu.set_library_handler("GetProcAddress", getprocaddress)
emu.set_library_handler("VirtualProtect", virtualprotect)

# Set a breakpoint at the real entry point to dump binary
emu.set_mnemonic_handler( "jmp", jmp_handler )

# Execute starting from the header entry point
emu.execute( start=emu.entry_point )
