# there must be Setup, KeyGen, Extract, Encrypt, Decrypt functions of AgEncID protocol
import time

import numpy as np

class PublicParamethers:
    def __init__(self, p, ord, t, E, G, alpha, param, n):
        self.p = p
        self.ord = ord
        self.t = t
        self.E = E
        self.G = G
        self.ord = E.order()
        self.alpha = alpha
        self.param = param
        self.n = n
    
def Setup(l: int, n: int) -> PublicParamethers:
    p = 1461501624496790265145448589920785493717258890819
    ord = 1461501624496790265145447380994971188499300027613
    t = 1208925814305217958863207

    E = EllipticCurve(GF(p), [0,3])
    G = E([1, 2])

    alpha = randint(2,p)

    Temp = G

    param = np.empty(
        (2 * n),
        dtype=sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field
    )
    for i in range(0, n):
        Temp = alpha * Temp
        param[i] = Temp

    Temp = alpha * Temp
    for i in range(n+1, 2*n):
        Temp = alpha * Temp
        param[i] = Temp

    pp = PublicParamethers(
        p=p,
        ord=ord,
        t=t,
        E=E,
        G=G,
        alpha=alpha,
        param=param,
        n=n
    )
    return pp

def KeyGen(pp: PublicParamethers):
    gamma = randint(2, pp.p)
    msk = gamma
    v = gamma * pp.G

    keyset = np.empty(
        (pp.n),
        dtype=sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field
    )
    for i in range(0, pp.n):
        keyset[i] = gamma * pp.param[i]
    
    return msk, v, keyset

def Extract(pp: PublicParamethers, S: list[int]):
    K_S = 0
    for j in S:
        K_S += pp.param[pp.n - j]

    return K_S

def Encrypt(pp: PublicParamethers, S: list[int], v, m):
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

def main(n: int):
    pp = Setup(l=None, n=n)

    msk, v, keyset = KeyGen(pp)

    S = [i for i in range(2, pp.n)]
    m = 123456787654321
    C = Encrypt(pp, S, v, m)

    i = 10
    m_ = Decrypt(pp, S, i, keyset[i], C)

    print("m: ", m)
    print("m':", m_)

if __name__ == "__main__":
    # main(100)
    time_evalation(10000)
