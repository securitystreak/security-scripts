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
class dalvik_app_password(linux_common.AbstractLinuxCommand):
###################################################################################################
     
     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          
###################################################################################################
     
     def calculate(self):

          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(0x41b0)

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None     
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "keystore":                    
                    proc_as = task.get_process_address_space()
                    self._config.PID = str(task.pid)
                    break

          # find stack
          for task, vma in dalvik.get_data_section_stack(self._config):
               # read length and password, they seem to have constant offset
               length = obj.Object('int', offset = vma.vm_start + 0x1982c, vm = proc_as)
               password = obj.Object('String', offset = vma.vm_start + 0x19830,
                              vm = proc_as, length = length)
               yield password

###################################################################################################
     
     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("Password", "20")                                 
                                        ])
          for password in data:

               self.table_row(     outfd,
                                   password)
