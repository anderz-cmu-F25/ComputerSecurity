import sys
import string


cipher_file = sys.argv[1]
key_file = sys.argv[2]
output_file = sys.argv[3]

with open(key_file) as f:
    key = f.read().strip()
    dec = dict()
    for i in range(26):
        dec[key[i]] = string.ascii_uppercase[i]

result = ""
with open(cipher_file) as f:
    txt = f.read().strip()
    for i in txt:
        if i in dec:
            result += dec[i]
        else:
            result += i
                      
with open(output_file, "w") as f:
    f.write(result)
