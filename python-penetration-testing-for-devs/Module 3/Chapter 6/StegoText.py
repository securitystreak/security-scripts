#!/usr/bin/env python
import sys
import urllib
import cStringIO

from optparse import OptionParser
from PIL import Image
from itertools import izip

def get_pixel_pairs(iterable):
    a = iter(iterable)
    return izip(a, a)


def set_LSB(value, bit):
    if bit == '0':
        value = value & 254
    else:
        value = value | 1
    return value

def get_LSB(value):
    if value & 1 == 0:
        return '0'
    else:
        return '1'

def extract_message(carrier, from_url=False):
    if from_url:
        f = cStringIO.StringIO(urllib.urlopen(carrier).read())
        c_image = Image.open(f)
    else:
        c_image = Image.open(carrier)
        
    pixel_list = list(c_image.getdata())
    
    message = ""

    for pix1, pix2 in get_pixel_pairs(pixel_list):
        message_byte = "0b"
        for p in pix1:
            message_byte += get_LSB(p)

        for p in pix2:
            message_byte += get_LSB(p)
            
        if message_byte == "0b00000000":
            break

        message += chr(int(message_byte,2))

    return message
    
def hide_message(carrier, message, outfile, from_url=False):
    message += chr(0)
    if from_url:
        f = cStringIO.StringIO(urllib.urlopen(carrier).read())
        c_image = Image.open(f)
    else:
        c_image = Image.open(carrier)
        
    c_image = c_image.convert('RGBA')

    out = Image.new(c_image.mode, c_image.size)

    width, height = c_image.size

    pixList = list(c_image.getdata())
    
    newArray = []
    
    for i in range(len(message)):
        charInt = ord(message[i])
        cb = str(bin(charInt))[2:].zfill(8)
        pix1 = pixList[i*2]
        pix2 = pixList[(i*2)+1]
        newpix1 = []
        newpix2 = []

        for j in range(0,4):
            newpix1.append(set_LSB(pix1[j], cb[j]))
            newpix2.append(set_LSB(pix2[j], cb[j+4]))

        newArray.append(tuple(newpix1))
        newArray.append(tuple(newpix2))

    newArray.extend(pixList[len(message)*2:])
    
    out.putdata(newArray)
    out.save(outfile)
    return outfile   





if __name__ == "__main__":

    
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--carrier", dest="carrier",
                help="The filename of the image used as the carrier.",
                metavar="FILE")
    parser.add_option("-m", "--message", dest="message",
                help="The text to be hidden.",
                metavar="FILE")
    parser.add_option("-o", "--output", dest="output",
                help="The filename the output file.",
                metavar="FILE")
    parser.add_option("-e", "--extract",
                  action="store_true", dest="extract", default=False,
                  help="Extract hidden message from carrier and save to output filename.")
    parser.add_option("-u", "--url",
                  action="store_true", dest="from_url", default=False,
                  help="Extract hidden message from carrier and save to output filename.")
     
    (options, args) = parser.parse_args()    
    if len(sys.argv) == 1:
        print "TEST MODE\nHide Function Test Starting ..."
        print hide_message('carrier.png', 'The quick brown fox jumps over the lazy dogs back.', 'messagehidden.png')
        print "Hide test passed, testing message extraction ..."
        print extract_message('messagehidden.png')
    else:
        if options.extract == True:
            if options.carrier is None:
                parser.error("a carrier filename -c is required for extraction")
            else:
                print extract_message(options.carrier, options.from_url)
        else:
            if options.carrier is None or options.message is None or options.output is None:
                parser.error("a carrier filename -c, message filename -m and output filename -o are required for steg")
            else:
                hide_message(options.carrier, options.message, options.output, options.from_url)


