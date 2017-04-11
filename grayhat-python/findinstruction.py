from immlib import *

def main(args):

    imm          = Debugger()
    search_code  = " ".join(args)

    search_bytes   = imm.Assemble( search_code )    
    search_results = imm.Search( search_bytes )

    for hit in search_results:

        # Retrieve the memory page where this hit exists
        # and make sure it's executable
        code_page   = imm.getMemoryPagebyAddress( hit )
        access      = code_page.getAccess( human = True )

        if "execute" in access.lower():
            imm.log("[*] Found: %s (0x%08x)" % ( search_code, hit ), address = hit )


    return "[*] Finished searching for instructions, check the Log window."