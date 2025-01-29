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
    
    gamma = randint(1, pairing.r)

    G = pairing.P1
    H = pairing.P2

    # Change P1 to random generator
    msk = (G, gamma)

    pk = [gamma * G, pairing.e(G, H)]
    temp = H
    for i in range(m):
        temp += gamma * temp
        pk.append(temp)

    return msk, pk, pairing

def Extract(msk, ID: int, pairing):
    G, gamma = msk

    sk_ID = pow(gamma + Hash(ID, pairing.r), -1, pairing.r) * G

    return sk_ID

def Encrypt(S: list[int], pk, pairing):
    k = randint(2, pairing.r)

    C1 = (-k) * pk[0]


    R = PolynomialRing(GF(pairing.r), "x")
    mul_poly = R(1)
    for ID in S:
        mul_poly *= R(x + Hash(ID, pairing.r))
    
    mul_poly = R(k) * mul_poly

    C2 = 0
    for power, coeff in mul_poly.monomial_coefficients().items():
        C2 += coeff * pk[power + 2]

    K = k * pk[1]

    return (C1, C2), K

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
    msk, pk, pairing = Setup(l=None, m=m)

    # S = [i for i in range(2, m)]
    S = [2, 4, 56]
    Hdr, K = Encrypt(S, pk, pairing)
    print(Hdr)
    print(K)

    # i = 10
    # m_ = Decrypt(pp, S, i, keyset[i], C)

    # print("m: ", m)
    # print("m':", m_)

if __name__ == "__main__":
    main(100)
    # time_evalation(100)
