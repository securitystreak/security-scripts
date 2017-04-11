import rabinkarp as rk
file_obj = open('sample_file.txt', 'rb')  # replace with a file you want to hash
chunk_size = 32
hash_list = set()
full_file = bytearray(file_obj.read())
h = rk.hash(full_file[0:chunk_size], 7)
hash_list.add(h)
old_byte = h[0]
for new_byte in full_file[chunk_size:]:
    h = rk.update(h, 7, old_byte, new_byte)
    hash_list.add(d)
    chunk = chunk[1:]
    chunk.append(new_byte)
    old_byte = chunk[0]

# Print the hash set for the file in an easy to read format
import pprint
pprint.pprint(hash_list)
