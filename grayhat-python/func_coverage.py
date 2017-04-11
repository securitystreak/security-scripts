from idaapi import *

class FuncCoverage(DBG_Hooks):

    # Our breakpoint handler
    def dbg_bpt(self, tid, ea):
        print "[*] Hit: 0x%08x" % ea
        return 1

# Add our function coverage debugger hook
debugger = FuncCoverage()
debugger.hook()

current_addr = ScreenEA()

# Find all functions and add breakpoints
for function in Functions(SegStart( current_addr ), SegEnd( current_addr )):
    AddBpt( function )
    SetBptAttr( function, BPTATTR_FLAGS, 0x0)


num_breakpoints = GetBptQty()

print "[*] Set %d breakpoints." % num_breakpoints
