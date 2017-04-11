#!/usr/bin/env python
import mmap
import contextlib
import argparse
from xml.dom import minidom 

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view

def main():
    parser = argparse.ArgumentParser(description="Dump specific event ids from a binary EVTX file into XML.")
    parser.add_argument("--cleanup", action="store_true", help="Cleanup unused XML entities (slower)"),
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    parser.add_argument("out", type=str, help="Path and name of the output file")
    parser.add_argument("--eventID", type=int, help="Event id that should be extracted")
    args = parser.parse_args()

    outFile = open(args.out, 'a+')
    with open(args.evtx, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            outFile.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>")
            outFile.write("<Events>")
            for xml, record in evtx_file_xml_view(fh):
                xmldoc = minidom.parseString(xml)
                event_id = xmldoc.getElementsByTagName('EventID')[0].childNodes[0].nodeValue
                if event_id == str(args.eventID):
                    outFile.write(xml)
                else:
                    continue
            outFile.write("</Events>")

if __name__ == "__main__":
    main()