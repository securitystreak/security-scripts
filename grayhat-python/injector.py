from ctypes import *

PROCESS_ALL_ACCESS  = 
VIRTUAL_MEM
PAGE_READWRITE

def write_data( data, length ):
    
    pass


# A switch to determine whether we want DLL or code injectio
def inject_dll( dll_path ):
    
    dll_len = len(dll_path)
    
    write_data( dll_path, dll_len )

    h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
    h_load_library = kernel32.GetProcAddress( h_kernel32, "LoadLibraryA" )
    
dll_len = len(dll_path)

# Get a handle to the process we are injecting into.
h_process = kernel32.OpenProcess(pyfault_defines.PROCESS_ALL_ACCESS, False, pid)

# Now we have to allocate enough bytes for the name and path of our DLL.
arg_address = kernel32.VirtualAllocEx(h_process,0,dll_len,pyfault_defines.VIRTUAL_MEM,pyfault_defines.PAGE_READWRITE)

# Write the path of the DLL into the previously allocated space. The pointer returned
written = ctypes.c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, ctypes.byref(written))

# Get a handle directly to kernel32.dll
h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")

# Get the address of LoadLibraryA
h_loadlib = kernel32.GetProcAddress(h_kernel32,"LoadLibraryA")
        
# Now we try to create the remote thread, with the entry point of 
thread_id = ctypes.c_ulong(0)
if not kernel32.CreateRemoteThread(h_process,None,0,h_loadlib,arg_address,0,ctypes.byref(thread_id)):
    raise faultx("CreateRemoteThread failed, unable to inject the DLL.")

# Return the threadid of the newly injected DLL 
return True