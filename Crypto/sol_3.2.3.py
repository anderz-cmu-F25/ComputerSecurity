import urllib.request
import urllib.error
import binascii
import sys
from copy import copy

# CONFIG
netid = "shuqinz2"
oracle_url = f"http://192.17.97.88:8080/mp3/{netid}/?"
block_size = 16

# Convert hex string to bytes
ciphertext_file = sys.argv[1]
with open(ciphertext_file) as f:
    ciphertext = bytes.fromhex(f.read().strip())

# Split into blocks
blocks = [list(ciphertext[i:i+block_size]) for i in range(0, len(ciphertext), block_size)]

def query_oracle(blocks) -> bool:
    try:
        url = oracle_url + binascii.hexlify(b''.join(bytes(block) for block in blocks)).decode()
        resp = urllib.request.urlopen(url)
        status = resp.getcode()
        return status
    except urllib.error.HTTPError as e:
        return e.code

def decrypt_block(blocks, idx=0):
    Plain_text = b""
    I = [0] * 16

    for i in range(15, -1, -1):
        # print(f"Solving for the {i}-th byte")

        C = blocks[idx][i]
        # print(f"C[{i}] = {C}", end=", ")

        for j in range(256):

            if C == j and i == 15:
                continue
            blocks[idx][i] = j
            response = query_oracle(blocks)
            if response == 404:
                G = j
                I[i] = G ^ 0x10
                P = I[i] ^ C
                Plain_text = bytes([P]) + Plain_text
                # print(f"G = [{j}] -> 404, P[{i}] = {hex(P)}, ", end="")

                pad = 0x0f
                for k in range(i, 16):
                    blocks[idx][k] = I[k] ^ pad
                    pad -= 1
                # print(f"C[15] = {pad+1}")

                break
    
    return Plain_text

Plain_text = b""
for i in range(0, len(blocks)-1):
    print(f"Solving for block {i}...")
    section = decrypt_block(blocks[i:i+2])
    print(f"Plain_text: {section}")
    Plain_text += section

print(Plain_text)
