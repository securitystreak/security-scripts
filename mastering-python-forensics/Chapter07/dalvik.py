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
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.flags as linux_flags
import volatility.plugins.linux.proc_maps as linux_proc_maps

# returns the task and the address space for the mapping of the data
# section within a specific process. what specifies which data section
# should be considered
def get_data_section(config, what):
    proc_maps = linux_proc_maps.linux_proc_maps(config).calculate()

    for task, vma in proc_maps:
        if not vma.vm_file:
            continue
        if not linux_common.get_path(task, vma.vm_file) == what:
            continue
        if not (vma.vm_flags & linux_flags.VM_READ and vma.vm_flags & linux_flags.VM_WRITE and not vma.vm_flags & linux_flags.VM_EXEC):
            continue

        yield task, vma

def get_data_section_libdvm(config):
    return get_data_section(config, "/system/lib/libdvm.so")

def get_data_section_dalvik_heap(config):
    for task, vma in get_data_section(config, "/dev/ashmem/dalvik-heap"):
        if vma.vm_pgoff == 0:
            yield task, vma

def get_data_section_stack(config):
    proc_maps = linux_proc_maps.linux_proc_maps(config).calculate()

    for task, vma in proc_maps:
        if not vma.vm_file:
            if vma.vm_start <= task.mm.start_stack and vma.vm_end >= task.mm.start_stack:
                yield task, vma

# registers a Volatiliy command line argument. Used by the dalvik_* plugins
def register_option_GDVM_OFFSET(config):
    linux_common.AbstractLinuxCommand.register_options(config)
    config.add_option('GDVM_OFFSET', short_option = 'o', default = None,
                      help = 'This is the offset (in hex) where the global struct gDvm can be found based on where libdvm is mapped in the process',
                      action = 'store', type = 'str')

def register_option_PID(config):
    config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on these Process IDs (possibly comma-separated)',
                      action = 'store', type = 'str')

#parses an ArrayObject and returns the contained ClassObjects
def parseArrayObject(arrayObject):
    proc_as = arrayObject.obj_vm

    count = 0
    while count < arrayObject.length:
        off = obj.Object('int', offset = arrayObject.contents0.obj_offset+count*0x4, vm = proc_as)
        if off != 0:
            field = obj.Object('Object', offset = off, vm = proc_as)
            yield field

        count += 1

# parses a Ljava/Util/ArrayList; and generates the list classes
def parseJavaUtilArrayList(arrayObjectAddr):
    proc_as = arrayObjectAddr.obj_vm
    # ref to Ljava/util/ArrayList;
    arrayObject = obj.Object('ArrayObject', offset = arrayObjectAddr, vm = proc_as)

    count = 0
    while count < arrayObject.length:

        # again getting a ArrayObject of type [Ljava/lang/Object
        arrayObject2 = obj.Object('ArrayObject', offset = arrayObject.contents0+count*0x4, vm = proc_as)

        # contents+4 bytes padding has a reference to the array on the heap
        # +0x8 would be the second element
        # we get a 'ref' here
        # and need to make an object out of it
        clazz = obj.Object('Object', offset = arrayObject2.contents1, vm = proc_as)
        # this is just the instance object, need the real Article object
        yield clazz.clazz

        count += 1

# parses a Ljava/Util/List; and generates the list classes
def parseJavaUtilList(objAddr):
    # given is a reference to a DataObject
    # e.g.ref to Ljava/util/Collections$SynchronizedRandomAccessList;
    dataObject = obj.Object('DataObject', offset = objAddr, vm = objAddr.obj_vm)
    return parseJavaUtilArrayList(dataObject.instanceData)

# just returns the dereferenced string
def getString(obj):
    return obj.dereference_as('String', length = linux_common.MAX_STRING_LENGTH)

# we get a 'StringObject' here
def parseJavaLangString(stringObj):

    if getString(stringObj.clazz.descriptor)+"" != "Ljava/lang/String;":
        return "This is not a StringObject"
    
    ###### Parsing StringObject ######
    count = obj.Object('int', offset = stringObj.obj_offset +
                       stringObj.clazz.getIFieldbyName('count').byteOffset, vm = stringObj.obj_vm)
    offset = obj.Object('int', offset = stringObj.obj_offset
                        + stringObj.clazz.getIFieldbyName('offset').byteOffset, vm = stringObj.obj_vm)

    value = obj.Object('address', offset = stringObj.obj_offset +
                       stringObj.clazz.getIFieldbyName('value').byteOffset, vm = stringObj.obj_vm)

    ###### Parsing ArrayObject ######
    arr = value.dereference_as('ArrayObject')

    # the string has count*2 (2 bytes for each character in unicode) characters
    ch = obj.Object('String', offset = arr.contents0.obj_offset+0x4*offset,
                    vm = stringObj.obj_vm, length = count*2, encoding = "utf16")
    return ch

# test if a given DvmGlobals object is the real deal
def isDvmGlobals(gDvm):
    # TODO: Do we need better heuristics here? At least for the
    # stackSize it might be unsafe to always assume 16K. But does the
    # trick for now.
    if gDvm.stackSize != 16384:
        return False
    if not "/system/framework/core.jar" in getString(gDvm.bootClassPathStr)+"":
        return False
    if gDvm.heapMaximumSize == 0:
        return False
    # TODO: Some more, or even better checks
    return True
