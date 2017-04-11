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
import volatility.plugins.linux.dalvik_find_gdvm_offset as dalvik_find_gdvm_offset
import volatility.plugins.linux.dalvik as dalvik
import sys, traceback

class dalvik_vms(linux_common.AbstractLinuxCommand):
    """Gather informationen about the Dalvik VMs running in the system"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        dalvik.register_option_GDVM_OFFSET(self._config)
        dalvik.register_option_PID(self._config)

    def calculate(self):

        offset = 0x0

        # this offset is valid throughout all processes
        if self._config.GDVM_OFFSET:
            # argument is given in hex
            gDvmOffset = int(self._config.GDVM_OFFSET, 16)
        else:
            gDvmOffset = dalvik_find_gdvm_offset.dalvik_find_gdvm_offset(self._config).calculate()

        for task, vma in dalvik.get_data_section_libdvm(self._config):

            gDvm = obj.Object('DvmGlobals', offset = vma.vm_start + gDvmOffset, vm = task.get_process_address_space())

            # sanity check: Is this a valid DvmGlobals object?
            #if not dalvik.isDvmGlobals(gDvm):
            #    continue
            yield task, gDvm

    def render_text(self, outfd, data):
        self.table_header(outfd, [("PID", "5"),
                                  ("name", "15"),
                                  ("heapStartingSize", "15"),
                                  ("heapMaximumSize", "15"),
                                  ("heapGrowthLimit", "15"),
                                  ("stackSize", "10"),
                                  ("tableSize", "10"),
                                  ("numDeadEntries", "15"),
                                  ("numEntries", "15")])

        for task, dvm in data:
            self.table_row(outfd,
                           task.pid,
                           task.comm,
                           dvm.heapStartingSize,
                           dvm.heapMaximumSize,
                           dvm.heapGrowthLimit,
                           dvm.stackSize,
                           dvm.loadedClasses.dereference().tableSize,
                           dvm.loadedClasses.dereference().numDeadEntries,
                           dvm.loadedClasses.dereference().numEntries)
