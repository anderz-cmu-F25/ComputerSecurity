from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
import math
import pbp  # assumes pbp.py is in the same directory
import sys

# --- Step 1: Load moduli ---
def load_moduli(filename):
    with open(filename, 'r') as f:
        return [int(line.strip(), 16) for line in f.readlines()]

# --- Step 2: Build Product Tree (not used directly, but here if needed) ---
def build_product_tree(moduli):
    tree = [moduli]
    while len(tree[-1]) > 1:
        level = []
        nodes = tree[-1]
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                level.append(nodes[i] * nodes[i + 1])
            else:
                level.append(nodes[i])
        tree.append(level)
    return tree

# --- Step 3: Find Shared Factors ---
def find_shared_factors(moduli):
    print("[*] Building full modulus product... (can be slow and memory-heavy)")
    M = 1
    for n in moduli:
        M *= n

    shared_factors = {}
    with open("keys", "w") as f:
        for i, n in enumerate(moduli):
            try:
                Ri = (M // n) % (n * n)
                g = math.gcd(Ri, n)
                if 1 < g < n:
                    p = g
                    q = n // g
                    shared_factors[i] = (p, q)
                    f.write(p)
                    f.write("\n")
                    f.write(q)
                    print(f"[+] Found shared factor in modulus #{i}:")
                    print(f"    p = {p}")
                    print(f"    q = {q}")
            except Exception as e:
                print(f"[!] Error processing modulus {i}: {e}")

    return shared_factors

# --- Step 4: Try Decrypting the Ciphertext ---
def try_decryption(shared_keys, moduli, ciphertext_file):
    with open(ciphertext_file, 'rb') as f:
        ciphertext = f.read().strip()

    for i, (p, q) in shared_keys.items():
        n = moduli[i]
        e = 65537
        phi = (p - 1) * (q - 1)
        try:
            d = inverse(e, phi)
            key = RSA.construct((int(n), int(e), int(d)))
            print(f"[*] Trying decryption with key from modulus #{i}...")
            try:
                plaintext = pbp.decrypt(key, ciphertext)
                print("[✓] SUCCESS! Decrypted plaintext:")
                print(plaintext.decode(errors='ignore'))  # may include binary garbage
                return  # exit after success
            except ValueError:
                print("[x] Failed to decrypt with this key.")
        except Exception as e:
            print(f"[!] Error constructing key: {e}")

# --- Main ---
if __name__ == '__main__':
    moduli_file = "moduli.hex"
    ciphertext_file = "3.3.1_ciphertext.enc.asc"

    print("[*] Loading moduli...")
    moduli = load_moduli(moduli_file)

    print("[*] Searching for shared prime factors...")
    shared_keys = find_shared_factors(moduli)

    # if not shared_keys:
    #     print("[x] No shared factors found.")
    #     sys.exit(1)

    # print("[*] Attempting decryption...")
    # try_decryption(shared_keys, moduli, ciphertext_file)
