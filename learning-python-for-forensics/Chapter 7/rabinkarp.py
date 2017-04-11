"""
Code From:
https://github.com/laurentluce/python-algorithms/

The MIT License (MIT)
Copyright (c) 2015 Laurent Luce

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


Aditional functionality added by CBRYCE for the book Learning Python for Forensics.
"""

def update(h, const, chunk_size, old_char, new_char):
    h = (h - int(old_char))/const
    h += (int(new_char) * (const ** (chunk_size-1)))
    return h

def hash(s, const):
    """Calculate the hash value of a string using base.
    Example: 'abc' = 97 x base^2 + 98 x base^1 + 99 x base^0
    @param s value to compute hash value for
    @param const int to use to compute hash value
    @return hash value
    """
    v = 0
    p = len(s)-1
    for i in reversed(range(p+1)):
        v += int(s[i]) * (const ** p)
        p -= 1

    return v
