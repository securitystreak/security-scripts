import binascii
import logging

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01


def checkHeader(filename, headers, size):
    """
    The checkHeader function reads a supplied size of the file and checks against known signatures to determine
    the file type.
    :param filename: The name of the file.
    :param headers: A list of known file signatures for the file type(s).
    :param size: The amount of data to read from the file for signature verification.
    :return: Boolean, True if the signatures match; otherwise, False.
    """
    with open(filename, 'rb') as infile:
        header = infile.read(size)
        hex_header = binascii.hexlify(header)
        for signature in headers:
            if hex_header == signature:
                return True
            else:
                pass
        logging.warn('The signature for {} ({}) does not match known signatures: {}'.format(
            filename, hex_header, headers))
        return False


def convertSize(size):
    """
    The convertSize function converts an integer representing bytes into a human-readable format.
    :param size: The size in bytes of a file
    :return: The human-readable size.
    """
    sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    index = 0
    while size > 1024:
        size /= 1024.
        index += 1
    return '{:.2f} {}'.format(size, sizes[index])

