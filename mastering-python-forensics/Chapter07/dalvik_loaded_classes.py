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
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.dalvik_vms as dalvik_vms
import volatility.plugins.linux.dalvik as dalvik
import sys, traceback

class dalvik_loaded_classes(linux_common.AbstractLinuxCommand):
    """Gather informationen about loaded classes a specific DalvikVM
    instance knows about"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        dalvik.register_option_GDVM_OFFSET(self._config)
        dalvik.register_option_PID(self._config)

    def calculate(self):
        proc_maps = linux_proc_maps.linux_proc_maps(self._config).calculate()
        dalvikVMs = dalvik_vms.dalvik_vms(self._config).calculate()

        for task, gDvm in dalvikVMs:
            for entry in gDvm.loadedClasses.dereference().get_entries():
                clazz = obj.Object('ClassObject', offset = entry, vm = gDvm.loadedClasses.obj_vm)
                yield task, clazz

    def render_text(self, outfd, data):
        self.table_header(outfd, [("PID", "5"),
                                  ("Offset", "10"),
                                  ("Descriptor", "70"),
                                  ("sourceFile", "30")])

        for task, clazz in data:
		if isinstance(clazz.obj_offset, int):
            		self.table_row(outfd,
			task.pid,
			hex(clazz.obj_offset),
                   	dalvik.getString(clazz.descriptor),
                   	dalvik.getString(clazz.sourceFile))
		else:
			self.table_row(outfd,
			task.pid,
			clazz.obj_offset,
                   	dalvik.getString(clazz.descriptor),
                   	dalvik.getString(clazz.sourceFile))
