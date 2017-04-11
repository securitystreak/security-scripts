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
class dalvik_app_lastInput(linux_common.AbstractLinuxCommand):
###################################################################################################
     
     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
          help = 'This is the offset (in hex) of system class RichInputConnection.java', action = 'store', type = 'str')

###################################################################################################
     
     def calculate(self):

          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(0x41b0)

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None     
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "putmethod.latin":                    
                    proc_as = task.get_process_address_space()
                    self._config.PID = str(task.pid)
                    break

          # use dalvik_loaded_classes plugin to find class offset if not specified
          if not self._config.CLASS_OFFSET:
              classes = dalvik_loaded_classes.dalvik_loaded_classes(self._config).calculate()
              for task, clazz in classes:
                   if (dalvik.getString(clazz.sourceFile)+"" == "RichInputConnection.java"):
                        self._config.CLASS_OFFSET = str(hex(clazz.obj_offset))
                        break

          # use dalvik_find_class_instance plugin to find a list of possible class instances
          instance = dalvik_find_class_instance.dalvik_find_class_instance(self._config).calculate()
          for sysClass, inst in instance:
               # get stringBuilder object
               stringBuilder = inst.clazz.getJValuebyName(inst, "mCommittedTextBeforeComposingText").Object.dereference_as('Object')
               # get superclass object
               abstractStringBuilder = stringBuilder.clazz.super.dereference_as('ClassObject')
               
               # array object of super class
               charArray = abstractStringBuilder.getJValuebyName(stringBuilder, "value").Object.dereference_as('ArrayObject')
               # get length of array object
               count = charArray.length
               # create string object with content of the array object
               text = obj.Object('String', offset = charArray.contents0.obj_offset,
               vm = abstractStringBuilder.obj_vm, length = count*2, encoding = "utf16")
               yield inst, text

###################################################################################################
     
     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("InstanceClass", "13"),
                                        ("lastInput", "20")                                 
                                        ])
          for inst, text in data:

               self.table_row(     outfd,
                                   hex(inst.obj_offset),
                                   text)
