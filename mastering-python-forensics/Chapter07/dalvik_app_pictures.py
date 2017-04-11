#!/usr/bin/python
#
# Copyright (C) 2015 Christian Hilgers, Holger Macht, Tilo Müller, Michael Spreitzenbarth
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

import volatility.plugins.linux.dalvik as dalvik
import volatility.plugins.linux.dalvik_loaded_classes as dalvik_loaded_classes
import volatility.plugins.linux.dalvik_find_class_instance as dalvik_find_class_instance

import time
from struct import *
###################################################################################################
class dalvik_app_pictures(linux_common.AbstractLinuxCommand):
###################################################################################################
     
     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
          help = 'This is the offset (in hex) of system class LocalAlbum.java', action = 'store', type = 'str')

###################################################################################################
     
     def calculate(self):

          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(0x41b0)

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None     
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "droid.gallery3d":                    
                    proc_as = task.get_process_address_space()
                    self._config.PID = str(task.pid)
                    break

          # use dalvik_loaded_classes plugin to find class offset if not specified
          if not self._config.CLASS_OFFSET:
              classes = dalvik_loaded_classes.dalvik_loaded_classes(self._config).calculate()
              for task, clazz in classes:
                   if (dalvik.getString(clazz.sourceFile)+"" == "LocalAlbum.java"):
                        self._config.CLASS_OFFSET = str(hex(clazz.obj_offset))
                        break

          # use dalvik_find_class_instance plugin to find a list of possible class instances
          instance = dalvik_find_class_instance.dalvik_find_class_instance(self._config).calculate()
          for sysClass, inst in instance:
               # boolean value, 1 for images, 0 for videos
               isImage = inst.clazz.getJValuebyName(inst, "mIsImage").int
               # sanity check
               if isImage != True:
                    continue
               # number of pictures, initilized with -1
               count = inst.clazz.getJValuebyName(inst, "mCachedCount").int
               # sanity check
               if count == -1:
                    continue
               # get album name
               album_name = inst.clazz.getJValuebyName(inst, "mName").Object.dereference_as('Object')
               
               # get pictures of album
               album_path = inst.clazz.getJValuebyName(inst, "mItemPath").Object.dereference_as('Object')
               iCache = album_path.clazz.getJValuebyName(album_path, "mChildren").Object.dereference_as('Object')
               hashmap = iCache.clazz.getJValuebyName(iCache, "mWeakMap").Object.dereference_as('Object')
               # in this table there is a reference to every single picture
               map_table = hashmap.clazz.getJValuebyName(hashmap, "table").Object.dereference_as('ArrayObject')
               # parse the table
               map_entries = dalvik.parseArrayObject(map_table)

               # for every reference of the table
               for field in map_entries:
                    entry = field.clazz.getJValuebyName(field, "value").Object.dereference_as('Object')
                    weak_reference_clazz = entry.clazz.super.dereference_as('ClassObject')
                    reference_clazz = weak_reference_clazz.super.dereference_as('ClassObject')
                    image_path = reference_clazz.getJValuebyName(entry, "referent").Object.dereference_as('Object')
                    image_weak_reference = image_path.clazz.getJValuebyName(image_path, "mObject").Object.dereference_as('Object')

                    # finally this is the instance of one picture class
                    local_image = reference_clazz.getJValuebyName(image_weak_reference, "referent").Object.dereference_as('Object')
                    # the interesting information is found in the superclass
                    local_media_item = local_image.clazz.super.dereference_as('ClassObject')

                    # get picture information
                    image_name = local_media_item.getJValuebyName(local_image, "caption").Object.dereference_as('Object')                    
                    image_size = local_media_item.getJValuebyName(local_image, "fileSize").int
                    image_lat = local_media_item.getJValuebyName(local_image, "latitude").longlong
                    image_long = local_media_item.getJValuebyName(local_image, "longitude").longlong
                    image_date_taken = local_media_item.getJValuebyName(local_image, "dateTakenInMs").ulonglong
                    image_filepath = local_media_item.getJValuebyName(local_image, "filePath").Object.dereference_as('Object')
                    image_width = local_media_item.getJValuebyName(local_image, "width").int
                    image_heigth = local_media_item.getJValuebyName(local_image, "height").int
                    
                    yield inst, image_name, album_name, image_size, image_lat, image_long, image_date_taken, image_width, image_heigth

###################################################################################################
     
     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("Instance", "10"),
                                        ("Name", "20"),
                                        ("Album", "10"),
                                        ("Size (kb)", "9"),
                                        ("Width", "5"),
                                        ("Heigth", "6"),
                                        ("Date taken", "19"),
                                        ("GPS Lat", "13"),
                                        ("GPS Long", "13")           
                                        ])

          for inst, image_name, album_name, image_size, image_lat, image_long, image_date_taken, image_width, image_heigth in data:

               # get strings from java string class
               img_name = dalvik.parseJavaLangString(image_name)
               a_name = dalvik.parseJavaLangString(album_name)

               # convert picture size from bytes to kilobytes
               size = image_size / 1024

               # convert epoch time to human readable date and time
               rawDate = image_date_taken / 1000
               date =    str(time.gmtime(rawDate).tm_mday) + "." + \
                         str(time.gmtime(rawDate).tm_mon) + "." + \
                         str(time.gmtime(rawDate).tm_year) + " " + \
                         str(time.gmtime(rawDate).tm_hour) + ":" + \
                         str(time.gmtime(rawDate).tm_min) + ":" + \
                         str(time.gmtime(rawDate).tm_sec)

               # convert gps coordinates to double values
               lat = pack('q', image_lat)
               lat = unpack('d', lat)
               lon = pack('q', image_long)
               lon = unpack('d', lon) 

               self.table_row(     outfd,
                                   hex(inst.obj_offset),
                                   img_name,
                                   a_name,
                                   size,
                                   image_width,
                                   image_heigth,
                                   date,
                                   lat,
                                   lon)
