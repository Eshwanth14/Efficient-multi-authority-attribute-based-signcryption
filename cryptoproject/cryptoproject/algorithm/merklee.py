import hashlib

def generate_merkle_tree(chunks):
    hashes = [hashlib.sha256(chunk).digest() for chunk in chunks]
    tree = hashes[:]
    while len(tree) > 1:
        tree_level = []
        for i in range(0, len(tree), 2):
            left = tree[i]
            right = tree[i + 1] if i + 1 < len(tree) else b''
            tree_level.append(hashlib.sha256(left + right).digest())
        tree = tree_level[:]
    return tree[0] if tree else b''