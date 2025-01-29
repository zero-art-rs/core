# there must be Setup, KeyGen, Extract, Encrypt, Decrypt functions of AgEncID protocol
import time
import hashlib

import numpy as np

load('src/mvp/bn381.sage')

def Hash(number: int, p: int) -> int:
    '''return hash of number modulo p'''
    number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

    sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

    return int(sha3_384_hash, 16) % p
    
def Setup(l: int, m: int):
    pairing = BN381Pairing()
    
    gamma = randint(1, pairing.r)

    #TODO: Change points G and H to random generators
    G = pairing.P1
    H = pairing.P2

    msk = (G, gamma)

    # Compute pk
    pk = [gamma * G, pairing.e(G, H), H] # pk = [w, v, H]
    temp = H
    for i in range(m): # Append h^(gamma^j) to pk, for j in [1, m]
        temp = gamma * temp
        pk.append(temp)

    return msk, pk, pairing

def Extract(msk, ID: int, pairing):
    G, gamma = msk

    sk_ID = pow(gamma + Hash(ID, pairing.r), -1, pairing.r) * G

    return sk_ID

def Encrypt(S: list[int], pk, pairing):
    k = randint(2, pairing.r)

    C1 = (pairing.r - k) * pk[0]

    # Compute C2 using polynomial where gamma^i is a random variable x^i
    R = PolynomialRing(GF(pairing.r), "x")
    mul_poly = R(1)
    for ID in S:
        mul_poly *= R(x + Hash(ID, pairing.r))
    
    mul_poly = R(k) * mul_poly

    # Compute C2 using coefficients in polynomial
    C2 = 0
    for power, coeff in mul_poly.monomial_coefficients().items():
        C2 += coeff * pk[power + 2]

    K = k * pk[1]

    return (C1, C2), K

def Decrypt(S, ID, sk_ID, Hdr, pk, pairing):
    C1, C2 = Hdr
    
    S_i = S.copy() # for beter readability remove ID from set S
    S_i.remove(ID)
    
    exponent = 1
    for ID_i in S_i:
        exponent = (exponent * Hash(ID_i, pairing.r)) % pairing.r
    exponent = pow(exponent, -1, pairing.r)

    # Compute H^(p_iS) using polynomial p_iS_polly
    R = PolynomialRing(GF(pairing.r), "x")
    p_iS_polly = R(1)
    for ID_i in S_i:
        p_iS_polly *= R(x + Hash(ID_i, pairing.r))
    
    # remove product of Hash(ID, pairing.r)
    prod = R(1)
    for ID_i in S_i:
        prod *= Hash(ID_i, pairing.r)
    
    p_iS_polly -= prod
    
    # Compute H^(p_iS) using coefficients in polynomial p_iS_polly
    Hp_iS = 0
    for power, coeff in p_iS_polly.monomial_coefficients().items():
        Hp_iS += coeff * pk[power + 1] # divided by gamma, so index is smaller

    K = pow(pairing.e(C1, Hp_iS) * pairing.e(sk_ID, C2), exponent)

    return K

# TODO: update time evaluation function
# def time_evalation(n: int):
#     time_start = time.time()
#     pp = Setup(l=None, n=n)
#     time_finish = time.time()
#     print(f"Setup time: {time_finish - time_start:0.3f} s.")

#     time_start = time.time()
#     msk, v, keyset = KeyGen(pp)
#     time_finish = time.time()
#     print(f"KeyGen time: {time_finish - time_start:0.3f} s.")

#     S = [i for i in range(2, pp.n)]
#     m = 123456787654321
#     time_start = time.time()
#     C = Encrypt(pp, S, v, m)
#     time_finish = time.time()
#     print(f"Encrypt time: {time_finish - time_start:0.3f} s.")

#     i = 10
#     time_start = time.time()
#     m_ = Decrypt(pp, S, i, keyset[i], C)
#     time_finish = time.time()
#     print(f"Decrypt time: {time_finish - time_start:0.3f} s.")

#     print("m: ", m)
#     print("m':", m_)

def main(m: int):
    msk, pk, pairing = Setup(l=None, m=m)

    ID = 4
    sk_ID = Extract(msk=msk, ID=ID, pairing=pairing)

    S = [i for i in range(m)]
    # S = [2, 4, 9, 11, 56]
    Hdr, K = Encrypt(S, pk, pairing)

    K_ = Decrypt(S=S, ID=ID, sk_ID=sk_ID, Hdr=Hdr, pk=pk, pairing=pairing)

    print(K)
    print("")
    print(K_)
    print("")
    print("K == K_:", K == K_)

if __name__ == "__main__":
    main(10)
    # time_evalation(100)
