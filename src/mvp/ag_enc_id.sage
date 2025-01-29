# there must be Setup, KeyGen, Extract, Encrypt, Decrypt functions of AgEncID protocol
import time
import hashlib

import numpy as np

load('src/mvp/bn381.sage')

def Hash(number: int, p: int):
    number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

    sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

    return int(sha3_384_hash, 16) % p
    
def Setup(l: int, m: int):
    pairing = BN381Pairing()
    
    gamma = randint(1, pairing.p)

    G = pairing.P1
    H = pairing.P2

    # Change P1 to random generator
    msk = (G, gamma)
    pk = [gamma * G, pairing.e(G, H)]
    temp = 0
    for i in range(m):
        temp += H
        pk.append(temp)

    return msk, pk

def Extract(pp, S: list[int]):
    K_S = 0
    for j in S:
        K_S += pp.param[pp.n - j]

    return K_S

def Encrypt(pp, S: list[int], v, m):
    t = randint(2, pp.p)

    K_S = Extract(pp, S)

    c1 = t * pp.G
    c2 = t * (v + K_S)
    c3 = m * pp.param[pp.n - 1].weil_pairing(t * pp.param[0], pp.ord)

    return c1, c2, c3

def Decrypt(pp, S: list[int], i: int, d_i, C):
    c1, c2, c3 = C

    b_iS = 0
    for j in S:
        if j != i:
            b_iS += pp.param[pp.n - j + i]

    top = (d_i + b_iS).weil_pairing(c1, pp.ord)
    down = pp.param[i].weil_pairing(c2, pp.ord)

    return c3 * (top / down)

def time_evalation(n: int):
    time_start = time.time()
    pp = Setup(l=None, n=n)
    time_finish = time.time()
    print(f"Setup time: {time_finish - time_start:0.3f} s.")

    time_start = time.time()
    msk, v, keyset = KeyGen(pp)
    time_finish = time.time()
    print(f"KeyGen time: {time_finish - time_start:0.3f} s.")

    S = [i for i in range(2, pp.n)]
    m = 123456787654321
    time_start = time.time()
    C = Encrypt(pp, S, v, m)
    time_finish = time.time()
    print(f"Encrypt time: {time_finish - time_start:0.3f} s.")

    i = 10
    time_start = time.time()
    m_ = Decrypt(pp, S, i, keyset[i], C)
    time_finish = time.time()
    print(f"Decrypt time: {time_finish - time_start:0.3f} s.")

    print("m: ", m)
    print("m':", m_)

def main(m: int):
    msk, pk = Setup(l=None, m=m)

    # msk, v, keyset = KeyGen(pp)

    # S = [i for i in range(2, pp.n)]
    # m = 123456787654321
    # C = Encrypt(pp, S, v, m)

    # i = 10
    # m_ = Decrypt(pp, S, i, keyset[i], C)

    # print("m: ", m)
    # print("m':", m_)

if __name__ == "__main__":
    main(100)
    # time_evalation(100)
