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
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.dalvik_vms as dalvik_vms
import volatility.plugins.linux.dalvik as dalvik
import sys, traceback

class dalvik_class_information(linux_common.AbstractLinuxCommand):
    """Gather informationen about a loaded class in the DalvikVM"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        dalvik.register_option_GDVM_OFFSET(self._config)
        dalvik.register_option_PID(self._config)

        self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
                                help = 'This is the offset (in hex) of a class within its address space. Usually taken from the dalvik_loaded_classes plugin',
                                action = 'store', type = 'str')

    def calculate(self):
        if self._config.CLASS_OFFSET:
            # argument is given in hex
            classOffset = int(self._config.CLASS_OFFSET, 16)
        else:
            print "No class offset given. Use dalvik_loaded_classes plugin to figure that out"
            return

        dalvikVMs = dalvik_vms.dalvik_vms(self._config).calculate()

        for task, gDvm in dalvikVMs:
            clazz = obj.Object('ClassObject', offset = classOffset, vm = gDvm.obj_vm)
            # is this an instance object? If so, get the actual system class
            if dalvik.getString(clazz.clazz.descriptor)+"" != "Ljava/lang/Class;":
                clazz = clazz.clazz
            yield clazz

    def render_text(self, outfd, data):
        self.table_header(outfd, [("objectSize", "10"),
                                  ("elementClass", "25"),
                                  ("arrayDim", "3"),
                                  ("interfaceCount", "3"),
                                  ("directMethodCount", "3"),
                                  ("virtualMethodCount", "3"),
                                  ("ifieldCount", "3"),
                                  ("ifieldRefCount", "3"),
                                  ("sfieldCount", "3")])

        for clazz in data:
            self.table_row(outfd,
                           clazz.objectSize,
                           dalvik.getString(clazz.elementClass.descriptor) or "",
                           clazz.arrayDim,
                           clazz.interfaceCount,
                           clazz.directMethodCount,
                           clazz.virtualMethodCount,
                           clazz.ifieldCount,
                           clazz.ifieldRefCount,
                           clazz.sfieldCount)

        print ""
        print "------- Instance fields ------"
        self.table_header(outfd, [("name", "40"),
                                  ("signature", "50"),
                                  ("accessFlags", "3"),
                                  ("byteOffset", "5")])


        for field in clazz.getIFields():
            self.table_row(outfd,
                           dalvik.getString(field.name),
                           dalvik.getString(field.signature),
                           field.accessFlags,
                           field.byteOffset)

        print ""
        print "------- Direct Methods ------"
        self.table_header(outfd, [("name", "50"),
                                  ("shorty", "20")])

        for method in clazz.getDirectMethods():
            self.table_row(outfd,
                           dalvik.getString(method.name),
                           dalvik.getString(method.shorty))

        print ""
        print "------- Virtual Methods ------"
        self.table_header(outfd, [("name", "50"),
                                  ("shorty", "20")])

        for method in clazz.getVirtualMethods():
            self.table_row(outfd,
                           dalvik.getString(method.name),
                           dalvik.getString(method.shorty))
