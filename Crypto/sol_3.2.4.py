import subprocess
import os
from pathlib import Path


def get_bit_length(file):
    return int(file.hex(), 16).bit_length()

def get_file(filename):
    with open(filename, "rb") as f:
        return f.read()

def write_file(filename, content):
    with open(filename, "wb") as f:
        return f.write(content)

RAW_PREFIX = "raw_prefix.hex"
PREFIX_PATH = "prefix.hex"
FASTCOLL_PATH = "./fastcoll"
FILE1 = "file1"
FILE2 = "file2"

# write_file(PREFIX_PATH, get_file(RAW_PREFIX)[:256])

# prefix_len = len(get_file(PREFIX_PATH))
# print(prefix_len)

# # loop until both outputs are 1023 bits
# attempt = 0
# while True:
#     attempt += 1
#     print(f"Attempt #{attempt}...")

#     # Run fastcoll
#     subprocess.run([FASTCOLL_PATH, "-p", PREFIX_PATH, "-o", FILE1, FILE2], check=True)
#     # subprocess.run([FASTCOLL_PATH, "-o", FILE1, FILE2], check=True)

#     b1_bits = get_bit_length(get_file(FILE1)[prefix_len:])
#     b2_bits = get_bit_length(get_file(FILE2)[prefix_len:])

#     print(f"b1 bits: {b1_bits}, b2 bits: {b2_bits}")

#     if b1_bits == 1023 and b2_bits == 1023:
#         print("Success: Both suffixes are 1023-bit")
#         with open("fastcoll_A", "wb") as f:
#             f.write(get_file(FILE1)[prefix_len:])

#         with open("fastcoll_B", "wb") as f:
#             f.write(get_file(FILE2)[prefix_len:])

#         break

#     elif attempt > 5:
#         print("Failed")
#         break

# b1 = int.from_bytes(get_file("fastcoll_A"), "big")
# b2 = int.from_bytes(get_file("fastcoll_B"), "big")

# # Step 1: Find p1 and p2 such that e is coprime to p-1
# from Crypto.Util.number import getPrime, isPrime
# import Crypto.Util.number as number
# import math

# e = 65537

# def get_prime_coprime_to(e, bits):
#     while True:
#         p = getPrime(bits)
#         if math.gcd(e, p - 1) == 1:
#             return p

# def generate_distinct_primes_with_coprime_e(e=65537, bits=400):
#     p1 = get_prime_coprime_to(e, bits)

#     while True:
#         p2 = get_prime_coprime_to(e, bits)
#         if p2 != p1:
#             return p1, p2

# # Example usage
# p1, p2 = generate_distinct_primes_with_coprime_e()
# print("p1 =", p1)
# print("p2 =", p2)
# print("p1 != p2:", p1 != p2)

# b1_exp = b1 << 1024
# b2_exp = b2 << 1024

# def getCRT(b1_exp, b2_exp, p1, p2):
#     N = p1 * p2

#     invOne = number.inverse(p2, p1)   # p2^(-1) mod p1
#     invTwo = number.inverse(p1, p2)   # p1^(-1) mod p2

#     return -(b1_exp * invOne * p2 + b2_exp * invTwo * p1) % N

# b0 = getCRT(b1_exp, b2_exp, p1, p2)

# k = 0
# limit = 1 << 1024
# while True:
#     b = b0 + k * p1 * p2
#     n1 = b1_exp + b
#     n2 = b2_exp + b

#     if n1 % p1 != 0 or n2 % p2 != 0:
#         k += 1
#         continue

#     q1 = n1 // p1
#     q2 = n2 // p2

#     if isPrime(q1) and isPrime(q2) and math.gcd(e, q1 - 1) == 1 and math.gcd(e, q2 - 1) == 1:

#         with open("sol_3.2.4_factorsA.hex", "w") as f:
#             f.write(hex(p1)[2:])
#             f.write("\n")
#             f.write(hex(q1)[2:])

#         with open("sol_3.2.4_factorsB.hex", "w") as f:
#             f.write(hex(p2)[2:])
#             f.write("\n")
#             f.write(hex(q2)[2:])

#         break

#     k += 1
#     if b >= limit:
#         print("Try new primes; b got too large")
#         break

def is_file_part_of_another(small_file, big_file):
    with open(small_file, "rb") as f1, open(big_file, "rb") as f2:
        small_data = f1.read()
        big_data = f2.read()
        return small_data in big_data

certA = "sol_3.2.4_certA.cer"
certB = "sol_3.2.4_certB.cer"

result1 = is_file_part_of_another(PREFIX_PATH, certA)
result2 = is_file_part_of_another(PREFIX_PATH, certB)

print("File A is part of File B" if result1 else "Not a match")
print("File A is part of File B" if result2 else "Not a match")
