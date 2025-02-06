import hashlib

def hash_mod(number: int, p: int) -> int:
    """return hash of number modulo p"""
    number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

    sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

    return int(sha3_384_hash, 16) % p

