import sys


cipher_file = sys.argv[1]
key_file = sys.argv[2]
modulo_file = sys.argv[3]
output_file = sys.argv[4]

with open(cipher_file) as f:
    cipher = int(f.read().strip(), 16)

with open(key_file) as f:
    key = int(f.read().strip(), 16)

with open(modulo_file) as f:
    modulo = int(f.read().strip(), 16)

plaintext = pow(cipher, key, modulo)

with open(output_file, "w") as f:
    f.write(hex(plaintext)[2:])
