fhan = None
try:
    fhan = open("main.hdb","r")
except IOError :
        raise IOError
hash_dict = {}

for hash_line in fhan :
    hash_line = hash_line.strip()
    hash,temp,name = hash_line.split(":")
    hash_dict[hash] = name

# print hash_dict
