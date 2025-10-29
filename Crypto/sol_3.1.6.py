import sys


def wha_hash(inStr: str) -> int:
    # Encode the input string into bytes
    input_bytes = inStr.encode('utf-8')

    mask = 0x3FFFFFFF
    outHash = 0

    for byte in input_bytes:
        intermediate_value = (
            ((byte ^ 0xCC) << 24) |
            ((byte ^ 0x33) << 16) |
            ((byte ^ 0xAA) << 8) |
            (byte ^ 0x55)
        )
        outHash = (outHash & mask) + (intermediate_value & mask)

    return hex(outHash)


# input_file = sys.argv[1]
# output_file = sys.argv[2]

# with open(input_file) as f:
#     input_str = f.read().strip()

# with open(output_file, "w") as f:
#     f.write(wha_hash(input_str)[2:])

s1 = "IN ORDER TO PREVENT CONFLICT YOU MIGHT PASS THIS SACRED CEREMONIAL OBJECT USED BY SOME NATIVE AMERICANS"
s2 = "IN ORDER TO PREVENT CONFLICT YOU MIGHT PASS THIS SACRED CEREMONIAL OBJECT USED BY SOME NATIVE AMERICANS\x4A\xB5"

print(f"Hash of {repr(s1)}: {(wha_hash(s1))}")
print(f"Hash of {repr(s2)}: {(wha_hash(s2))}")