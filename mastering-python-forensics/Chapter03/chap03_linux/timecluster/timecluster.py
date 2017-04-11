#!/usr/bin/python

from datetime import date
import numpy as np
import os
from os.path import join
from sklearn.cluster import DBSCAN
import sys

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


def _calc_clusters(data, eps, minsamples):
    samples = np.array(data)
    db = DBSCAN(eps=eps, min_samples=minsamples).fit(samples)
    return (db.labels_, db.core_sample_indices_)

def calc_atime_clusters(stats, days=1, mincluster=5):
    """Clusters files regarding to their 'last access' date.

    Arguments:
    stats -- file metadata as returned as 2nd element by gen_filestats
    days  -- approx. size of a cluster (default: accessed on same day)
    mincluster -- min. number of files to make a new cluster

    Returns:
    Tuple with array denoting cluster membership
    and indexes of representatives of cluster cores"""

    atimes = map(lambda x: [x.st_atime], stats)
    return _calc_clusters(atimes, days * 24 * 3600, mincluster)

def calc_mtime_clusters(stats, days=1, mincluster=5):
    """Clusters files regarding to their 'last modified' date.

    Arguments:
    stats -- file metadata as returned as 2nd element by gen_filestats
    days  -- approx. size of a cluster (default: accessed on same day)
    mincluster -- min. number of files to make a new cluster

    Returns:
    Tuple with array denoting cluster membership
    and indexes of representatives of cluster cores"""

    mtimes = map(lambda x: [x.st_mtime], stats)
    return _calc_clusters(mtimes, days * 24 * 3600, mincluster)


def calc_histogram(labels, core_indexes, timestamps):
    # reserve space for outliers (label -1), even if there are none
    num_entries = len(set(labels)) if -1 in labels else len(set(labels))+1

    counters = [0] * num_entries
    coredates = [0] * num_entries
    
    for c in core_indexes:
        i = int(c)
        coredates[int(labels[i])+1] = timestamps[i]

    for l in labels:
        counters[int(l)+1] += 1

    return zip(coredates, counters)

def print_histogram(histogram):
    # sort histogram by core time stamps
    sort_histo = sorted(histogram, cmp=lambda x,y: cmp(x[0],y[0]))

    print '[date around] [number of files]'
    for h in sort_histo:
        if h[0] == 0:
            print '<outliers>',
        else:
            t = date.fromtimestamp(h[0]).isoformat()
            print t,
        print '    %6d' % h[1]
        
    

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage %s base_directory [number of days in one cluster]' % sys.argv[0]
        sys.exit(1)

    days = 1
    if len(sys.argv) > 2:
        days = int(sys.argv[2])

    names, stats = gen_filestats(sys.argv[1])

    print '%d files to analyze...' % len(names)

    atime_labels, atime_cores = calc_atime_clusters(stats, days)
    mtime_labels, mtime_cores = calc_mtime_clusters(stats, days)

    atimes = map(lambda x: x.st_atime, stats)
    mtimes = map(lambda x: x.st_mtime, stats)

    ahisto = calc_histogram(atime_labels, atime_cores, atimes)
    mhisto = calc_histogram(mtime_labels, mtime_cores, mtimes)

    print "\n=== Access time histogram ==="
    print_histogram(ahisto)

    print "\n=== Modification time histogram ==="
    print_histogram(mhisto)
