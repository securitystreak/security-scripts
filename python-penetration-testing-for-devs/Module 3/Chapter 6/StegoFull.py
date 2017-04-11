#!/usr/bin/env python
from optparse import OptionParser
from PIL import Image

def HideMessage(carrier, message, outfile):
    cImage = Image.open(carrier)
    hide = Image.open(message)
    hide = hide.resize(cImage.size)
    hide = hide.convert('1')
    out = Image.new(cImage.mode, cImage.size)

    width, height = cImage.size

    newArray = []
    
    for h in range(height):
        for w in range(width):
            ip = cImage.getpixel((w,h))
            hp = hide.getpixel((w,h))
            if hp == 0: # Force 0 And with 254
                newred = ip[0] & 254
            else:       # Force 1 Or with 1
                newred = ip[0] | 1

            newArray.append((newred, ip[1], ip[2]))

    out.putdata(newArray)
    out.save(outfile)
    print "Steg image saved to " + outfile    

def ExtractMessage(carrier, outfile):
    cImage = Image.open(carrier)
    out = Image.new('L', cImage.size)

    width, height = cImage.size
    
    newArray = []

    for h in range(height):
        for w in range(width):
            ip = cImage.getpixel((w,h))
            if ip[0] & 1 == 0:
                newArray.append(0)
            else:
                newArray.append(255)

    out.putdata(newArray)
    out.save(outfile)
    print "Message extracted and saved to " + outfile
    
if __name__ == "__main__":
    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--carrier", dest="carrier",
                help="The filename of the image used as the carrier.",
                metavar="FILE")
    parser.add_option("-m", "--message", dest="message",
                help="The filename of the image that will be hidden.",
                metavar="FILE")
    parser.add_option("-o", "--output", dest="output",
                help="The filename the hidden image will be extracted to.",
                metavar="FILE")
    parser.add_option("-e", "--extract",
                  action="store_true", dest="extract", default=False,
                  help="Extract hidden image from carrier and save to output filename.")

    (options, args) = parser.parse_args()    

    if options.extract == True:
        if options.carrier is None or options.output is None:
            parser.error("a carrier filename -c and output file -o are required for extraction")
        else:
            ExtractMessage(options.carrier, options.output)
    else:
        if options.carrier is None or options.message is None or options.output is None:
            parser.error("a carrier filename -c, message filename -m and output filename -o are required for steg")
        else:
            HideMessage(options.carrier, options.message, options.output)


