import immlib
import immutils

# This is Nico's function that looks for the correct
# basic block that has our desired ret instruction 
# this is used to find the proper hook point for RtlAllocateHeap
def getRet(imm, allocaddr, max_opcodes = 300):
    addr = allocaddr

    for a in range(0, max_opcodes):
        op = imm.disasmForward( addr )
        if op.isRet():
            if op.getImmConst() == 0xC:
                op = imm.disasmBackward( addr, 3)                   
                return op.getAddress()
        addr = op.getAddress()

    return 0x0

# A simple wrapper to just print out the hook
# results in a friendly manner, it simply checks the hook
# address against the stored addresses for RtlAllocateHeap, RtlFreeHeap
def showresult(imm, a, rtlallocate, extra = ""):

    if a[0] == rtlallocate:
        imm.Log("RtlAllocateHeap(0x%08x, 0x%08x, 0x%08x) <- 0x%08x %s" % ( a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3]  )
        return "done"
    else:
        imm.Log("RtlFreeHeap(0x%08x, 0x%08x, 0x%08x) %s" % (a[1][0], a[1][1], a[1][2], extra)  )


def main(args):

    imm          = immlib.Debugger()
    Name         = "hippie"

    fast = imm.getKnowledge( Name )
    if fast:
        # We have previously set hooks, so we must want
        # to print the results
        hook_list = fast.getAllLog()

        rtlallocate, rtlfree = imm.getKnowledge("FuncNames")

        for a in hook_list:
            ret = showresult( imm, a, rtlallocate )

        return "Logged: %d hook hits. Results output to log window." % len(hook_list)

    # We want to stop the debugger before monkeying around
    imm.Pause()

    rtlfree     = imm.getAddress("ntdll.RtlFreeHeap")
    rtlallocate = imm.getAddress("ntdll.RtlAllocateHeap")

    module = imm.getModule("ntdll.dll")
    if not module.isAnalysed():
        imm.analyseCode( module.getCodebase() )

    # We search for the correct function exit point
    rtlallocate = getRet( imm, rtlallocate, 1000 )
    imm.Log("RtlAllocateHeap hook: 0x%08x" % rtlallocate)

    # Store the hook points
    imm.addKnowledge("FuncNames",  ( rtlallocate, rtlfree ) )

    # Now we start building the hook
    fast = immlib.STDCALLFastLogHook( imm )

    # We are trapping RtlHeapAllocate at the end of the function
    imm.Log("Logging on Alloc 0x%08x" % rtlallocate)
    fast.logFunction( rtlallocate )
    fast.logBaseDisplacement( "EBP",    8)
    fast.logBaseDisplacement( "EBP",  0xC)
    fast.logBaseDisplacement( "EBP", 0x10)
    fast.logRegister( "EAX" )      

    # We are trapping RtlHeapFree at the head of the function
    imm.Log("Logging on RtlHeapFree  0x%08x" % rtlfree)
    fast.logFunction( rtlfree, 3 )

    # Set the hook
    fast.Hook()

    # Store the hook object so we can retrieve results later
    imm.addKnowledge(Name, fast, force_add = 1)

    return "Hooks set, press F9 to continue the process."