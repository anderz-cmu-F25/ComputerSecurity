from pymd5 import md5, padding
from urllib.parse import quote_from_bytes
import sys

query_file = sys.argv[1]
command3_file = sys.argv[2]
output_file = sys.argv[3]

with open(query_file) as f:
    query = f.read().strip()

with open(command3_file) as f:
    command3 = f.read().strip()

# Extract original token and message
parts = query.split("&")
token = [p for p in parts if p.startswith("token=")][0].split("=")[1]
original_msg = query[query.find("user="):]  # part of message after token
msg_length = 8 + len(original_msg)  # 8-byte secret prefix

# Create new hash starting from original state
pad = padding(msg_length * 8)
h = md5(state=token, count=(msg_length + len(pad)) * 8)
h.update(command3)
new_token = h.hexdigest()

# Rebuild final forged query
parts = [f"token={new_token}"] + parts[1:]  # replace token
forged_query = "&".join(parts) + quote_from_bytes(pad) + command3

with open(output_file, "w") as f:
    f.write(forged_query)
