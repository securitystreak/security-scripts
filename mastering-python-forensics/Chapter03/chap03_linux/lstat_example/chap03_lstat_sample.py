from datetime import datetime as dt
from os import lstat

stat_info = lstat('/tmp/foo')

atime = dt.utcfromtimestamp(stat_info.st_atime)
mtime = dt.utcfromtimestamp(stat_info.st_mtime)
ctime = dt.utcfromtimestamp(stat_info.st_ctime)

print 'File mode bits:      %s' % oct(stat_info.st_mode)
print 'Inode number:        %d' % stat_info.st_ino
print '# of hard links:     %d' % stat_info.st_nlink
print 'Owner UID:           %d' % stat_info.st_uid
print 'Group GID:           %d' % stat_info.st_gid
print 'File size (bytes)    %d' % stat_info.st_size
print 'Last read (atime)    %s' % atime.isoformat(' ')
print 'Last write (mtime)   %s' % mtime.isoformat(' ')
print 'Inode change (ctime) %s' % ctime.isoformat(' ')

# here starts the extension of the example
import stat

if stat.S_ISUID & stat_info.st_mode:
    print 'SUID mode set!'

if stat.S_ISGID & stat_info.st_mode:
    print 'SGID mode set!'

if stat.S_ISVTX & stat_info.st_mode:
    print 'Sticky mode set!'
