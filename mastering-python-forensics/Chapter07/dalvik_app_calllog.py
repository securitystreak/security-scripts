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
###################################################################################################
class dalvik_app_calllog(linux_common.AbstractLinuxCommand):
###################################################################################################
     
     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
          help = 'This is the offset (in hex) of system class PhoneCallDetails.java', action = 'store', type = 'str')

###################################################################################################
     
     def calculate(self):
          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(hex(0x41b0))

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "ndroid.contacts":
                    proc_as = task.get_process_address_space()
                    if not self._config.PID:
                         self._config.PID = str(task.pid)
                    break

          # use dalvik_loaded_classes plugin to find class offset if not specified
          if not self._config.CLASS_OFFSET:
              classes = dalvik_loaded_classes.dalvik_loaded_classes(self._config).calculate()
              for task, clazz in classes:
                   if (dalvik.getString(clazz.sourceFile)+"" == "PhoneCallDetails.java"):
                        self._config.CLASS_OFFSET = str(hex(clazz.obj_offset))
                        break

          # use dalvik_find_class_instance plugin to find a list of possible class instances
          instances = dalvik_find_class_instance.dalvik_find_class_instance(self._config).calculate()
          for sysClass, inst in instances:
               callDetailsObj = obj.Object('PhoneCallDetails', offset = inst, vm = proc_as)
               # access type ID field for sanity check
               typeID = int(callDetailsObj.callTypes.contents0)
               # valid type ID must be 1,2 or 3
               if (typeID == 1 or typeID == 2 or typeID == 3):
                    yield callDetailsObj

###################################################################################################
     
     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("InstanceClass", "13"),
                                        ("Date", "19"),
                                        ("Contact", "20"),
                                        ("Number", "15"),
                                        ("Duration", "13"),
                                        ("Iso", "3"),
                                        ("Geocode", "15"),
                                        ("Type", "8")                                      
                                        ])
          for callDetailsObj in data:
               # convert epoch time to human readable date and time
               rawDate = callDetailsObj.date / 1000
               date =    str(time.gmtime(rawDate).tm_mday) + "." + \
                         str(time.gmtime(rawDate).tm_mon) + "." + \
                         str(time.gmtime(rawDate).tm_year) + " " + \
                         str(time.gmtime(rawDate).tm_hour) + ":" + \
                         str(time.gmtime(rawDate).tm_min) + ":" + \
                         str(time.gmtime(rawDate).tm_sec)

               # convert duration from seconds to hh:mm:ss format
               duration =     str(callDetailsObj.duration / 3600) + "h " + \
                              str((callDetailsObj.duration % 3600) / 60) + "min " + \
                              str(callDetailsObj.duration % 60) + "s"

               # replace call type ID by string
               callType = int(callDetailsObj.callTypes.contents0)
               if callType == 1:
                    callType = "incoming"
               elif callType == 2:
                    callType = "outgoing"
               elif callType == 3:
                    callType = "missed"
               else:
                    callType = "unknown"

               self.table_row(     outfd,
                                   hex(callDetailsObj.obj_offset),
                                   date,
                                   dalvik.parseJavaLangString(callDetailsObj.name.dereference_as('StringObject')),
                                   dalvik.parseJavaLangString(callDetailsObj.formattedNumber.dereference_as('StringObject')),
                                   duration,               
                                   dalvik.parseJavaLangString(callDetailsObj.countryIso.dereference_as('StringObject')),
                                   dalvik.parseJavaLangString(callDetailsObj.geoCode.dereference_as('StringObject')),
                                   callType)
