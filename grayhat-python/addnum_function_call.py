import sys

sys.path.append("C:\\PyEmu")
sys.path.append("C:\\PyEmu\\lib")

from PyEmu import *

    
def ret_handler(emu, address):
        
    num1 = emu.get_stack_argument("arg_0")
    num2 = emu.get_stack_argument("arg_4")
    sum  = emu.get_register("EAX")
    
    print "[*] Function took: %d, %d and the result is %d" % ( num1, num2, sum)
        
    return True


emu = IDAPyEmu()

# Load the binary's code segment
code_start = SegByName(".text")
code_end   = SegEnd( code_start )

while code_start <= code_end:
    emu.set_memory( code_start, GetOriginalByte(code_start), size=1 )
    code_start += 1

print "[*] Finished loading code section into memory."

# Load the binary's data segment
data_start = SegByName(".data")
data_end   = SegEnd( data_start )

while data_start <= data_end:
    emu.set_memory( data_start, GetOriginalByte(data_start), size=1)
    data_start += 1

print "[*] Finished loading data section into memory."

# Set EIP to start executing at the function head
emu.set_register("EIP", 0x00401000)

# Set up the ret handler
emu.set_mnemonic_handler("ret", ret_handler)

# Set the function parameters for the call
emu.set_stack_argument(0x8, 0x00000001, name="arg_0")
emu.set_stack_argument(0xc, 0x00000002, name="arg_4")

# There are 10 instructions in this function
emu.execute( steps = 10 )

print "[*] Finished function emulation run."