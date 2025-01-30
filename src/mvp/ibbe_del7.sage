# IBBE protocol by Cecile Delerablee (2007)
import hashlib

load('./bn381.sage')

def hash_mod(number: int, p: int) -> int:
    """return hash of number modulo p"""
    number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

    sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

    return int(sha3_384_hash, 16) % p

class IBBE_Del7:
    def __init__(self):
        self.pairing = BN381Pairing()

    def Setup(self, number_of_users: int):        
        gamma = randint(1, self.pairing.r)

        G = randint(1, self.pairing.r) * self.pairing.P2
        H = randint(1, self.pairing.r) * self.pairing.P1

        msk = (G, gamma)

        pk = [gamma * G, self.pairing.e(H, G), H] # pk = [w, v, H]

        # Append (gamma^j) H to pk, for j in [1, number_of_users]
        temp = H
        for i in range(number_of_users):
            temp = gamma * temp
            pk.append(temp)

        return msk, pk

    def Extract(self, msk, ID: int):
        G, gamma = msk

        sk_ID = pow(gamma + hash_mod(ID, self.pairing.r), -1, self.pairing.r) * G

        return sk_ID

    def Encrypt(self, S: list[int], pk):
        k = randint(2, self.pairing.r)

        C1 = (self.pairing.r - k) * pk[0]

        # Compute mul_polly, for which, having gamma as x, mul_poolly H = C2
        R = PolynomialRing(GF(self.pairing.r), "x")
        mul_polly = R(1)
        for ID in S:
            mul_polly *= R(x + hash_mod(ID, self.pairing.r))
        
        mul_polly = R(k) * mul_polly

        # Compute C2 using coefficients in polynomial mul_polly
        C2 = 0
        for power, coeff in mul_polly.monomial_coefficients().items():
            C2 += coeff * pk[power + 2]

        K = pow(pk[1], k)

        return (C1, C2), K

    def Decrypt(self, S, ID, sk_ID, Hdr, pk):
        C1, C2 = Hdr

        exponent = 1
        for ID_i in S:
            if ID_i != ID:
                exponent = (exponent * hash_mod(ID_i, self.pairing.r)) % self.pairing.r
        exponent = pow(exponent, -1, self.pairing.r)

        # Using polynomial p_iS_polly we will compute H^(p_iS) 
        R = PolynomialRing(GF(self.pairing.r), "x")
        p_iS_polly = R(1)
        for ID_i in S:
            if ID_i != ID:
                p_iS_polly *= R(x + hash_mod(ID_i, self.pairing.r))
        
        # remove product of Hash(ID, self.pairing.r)
        prod = R(1)
        for ID_i in S:
            if ID_i != ID:
                prod *= hash_mod(ID_i, self.pairing.r)
        
        p_iS_polly -= prod
        
        # Compute H^(p_iS) using coefficients in polynomial p_iS_polly
        Hp_iS = 0
        for power, coeff in p_iS_polly.monomial_coefficients().items():
            Hp_iS += coeff * pk[power + 1] # divided by gamma, so index is smaller

        K = pow(self.pairing.e(Hp_iS, C1) * self.pairing.e(C2, sk_ID), exponent)

        return K

def IBBE_Del7_usage_example(number_of_users: int=10):
    ibbe = IBBE_Del7()

    msk, pk = ibbe.Setup(number_of_users=number_of_users)

    ID = 4
    sk_ID = ibbe.Extract(msk=msk, ID=ID)

    S = [i for i in range(number_of_users)]
    Hdr, K = ibbe.Encrypt(S=S, pk=pk)

    K_ = ibbe.Decrypt(S=S, ID=ID, sk_ID=sk_ID, Hdr=Hdr, pk=pk)

    print("K: ", K)
    print("")
    print("K':", K_)
    print("")
    print("K == K':", K == K_)
