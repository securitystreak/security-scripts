#!/usr/bin/env python

from datetime import datetime
from matplotlib.dates import DateFormatter
import matplotlib.pyplot as plt
import os
from os.path import join
import sys

# max. number of bars on the histogram
NUM_BINS = 200

def gen_filestats(basepath):
    """Collects metadata about a directory tree.
    
    Arguments:
    basepath -- root directory to start from

    Returns:
    Tuple with list of file names and list of
    stat results."""

    filenames = []
    filestats = []
    
    for root, dirs, files in os.walk(basepath):
        for f in files:
            fullname = join(root, f)
            filenames.append(fullname)
            filestats.append(os.lstat(fullname))
    return (filenames, filestats)

def show_date_histogram(times, heading='', block=False):
    """Draws and displays a histogram over the given timestamps.

    Arguments:
    times -- array of time stamps as seconds since 1970-01-01
    heading -- heading to write to the drawing"""

    fig, ax = plt.subplots()

    times = map(lambda x: datetime.fromtimestamp(x).toordinal(), times)

    ax.hist(times, NUM_BINS)
    plt.xlabel('Date')
    plt.ylabel('# of files')
    plt.title(heading)
    
    ax.autoscale_view()

    ax.xaxis.set_major_formatter(DateFormatter('%Y-%m-%d'))
    fig.autofmt_xdate()

    fig.show()
    if block:
        plt.show()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage %s base_directory' % sys.argv[0]
        sys.exit(1)

    path = sys.argv[1]

    (names, stats) = gen_filestats(path)
    
    # extract time stamps
    mtimes = map(lambda x: x.st_mtime, stats)
    atimes = map(lambda x: x.st_atime, stats)

    show_date_histogram(mtimes, 'mtimes of ' + path)
    show_date_histogram(atimes, 'atimes of ' + path, True)

    
