# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Holger Macht
@license:      GNU General Public License 2.0 or later
@contact:      holger@homac.de
"""

import volatility.obj as obj
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.dalvik_vms as dalvik_vms
import volatility.plugins.linux.dalvik as dalvik
import sys, traceback

class dalvik_find_class_instance(linux_common.AbstractLinuxCommand):
    """Gather information about the Mirrored application"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        dalvik.register_option_PID(self._config)
        self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
                                help = 'This is the offset (in hex) of a system class you want to find an instance of. Usually taken from the dalvik_loaded_classes plugin',
                                action = 'store', type = 'str')

    def calculate(self):
        classOffset = 0x0
        if self._config.CLASS_OFFSET:
            # argument is given in hex
            classOffset = int(self._config.CLASS_OFFSET, 16)
        else:
            print "No class offset given. Use dalvik_loaded_classes plugin to figure that out"
            return

        if not self._config.PID:
            print "This plugin requires a PID to be given via the '-p' switch"
            return

        start = 0
        end = 0
        proc_as = None
        for task, vma in dalvik.get_data_section_dalvik_heap(self._config):
            start = vma.vm_start
            end = vma.vm_end
            proc_as = task.get_process_address_space()
            break

        offset = start
                  
        while offset < end:
            refObj = obj.Object('Object', offset = offset, vm = proc_as)

            if refObj.clazz == classOffset:
                sysClass = refObj.clazz
                yield sysClass, offset
            # we assume 8 byte alignment, this should be quite save and reduces the scan effort
            offset += 0x8

    def render_text(self, outfd, data):
        self.table_header(outfd, [("SystemClass", "50"),
                                  ("InstanceClass", "50")])
        for sysClass, clazz in data:
            self.table_row(outfd,
                           hex(int(sysClass)),
                           hex(int(clazz)))
