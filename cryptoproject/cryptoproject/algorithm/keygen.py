import random

def generate_key(length):
    key = b''
    for i in range(length):
        key += bytes([random.randint(0, 255)])
    return key