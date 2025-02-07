# Forward Secure IBBE protocol baseed on Cecile Delerablee (2007)
import hashlib

load('./bn381.sage')

class FS_IBBE_Del7:
    def __init__(self):
        self.pairing = BN381Pairing()

        self.PollyRing = PolynomialRing(GF(self.pairing.r), "x")

    def Setup(self, number_of_users: int):        
        gamma = self.randint()

        H = self.randint() * self.pairing.P1
        G = self.randint() * self.pairing.P2

        msk = (G, gamma)

        pk_O = [gamma * G, self.pairing.e(H, G), H, self.inverse(gamma) * H] # pk = [w, v, h]

        pk_H = [self.inverse(gamma) * H, H]
        # Append (gamma^j) H to pk, for j in [1, number_of_users]
        temp = H
        for i in range(number_of_users):
            temp = gamma * temp
            pk_H.append(temp)

        return msk, (pk_O, pk_H)

    def Extract(self, msk, ID: int):
        G, gamma = msk

        presk_ID = self.inverse(gamma + self.hash_mod(ID)) * G

        return presk_ID

    def KeyGen(self, r, pk, presk_ID):
        pk_O, pk_H = pk

        sk = self.inverse(r) * presk_ID

        for i, H_i in enumerate(pk_H):
            pk_H[i] = r * H_i

        return sk

    def Encrypt(self, S: list[int], pk):
        k = self.randint()

        pk_O, pk_H = pk

        C1 = (self.pairing.r - k) * pk_O[0]

        # Compute mul_polly, for which, having gamma as x, mul_poolly H = C2
        mul_polly = self.PollyRing(1)
        for ID in S:
            mul_polly *= self.PollyRing(x + self.hash_mod(ID))
        
        mul_polly = self.PollyRing(k) * mul_polly

        # Compute C2 using coefficients in polynomial mul_polly
        C2 = 0
        for power, coeff in mul_polly.monomial_coefficients().items():
            C2 += coeff * pk_H[power + 1]

        K = pow(pk_O[1], k)

        return (C1, C2), K

    def Decrypt(self, S, ID, sk_ID, Hdr, pk, r):
        C1, C2 = Hdr
        pk_O, pk_H = pk

        exponent = 1
        for ID_i in S:
            if ID_i != ID:
                exponent = (exponent * self.hash_mod(ID_i)) % self.pairing.r
        exponent = self.inverse(exponent)

        # Using polynomial p_iS_polly we will compute H^(p_iS)
        p_iS_polly = self.PollyRing(1)
        for ID_i in S:
            if ID_i != ID:
                p_iS_polly *= self.PollyRing(x + self.hash_mod(ID_i))
        
        # remove product of Hash(ID, self.pairing.r)
        prod = self.PollyRing(1)
        for ID_i in S:
            if ID_i != ID:
                prod *= self.hash_mod(ID_i)

        # Compute H^(p_iS) using coefficients in polynomial p_iS_polly
        Hp_iS = 0
        for power, coeff in p_iS_polly.monomial_coefficients().items():
            Hp_iS += coeff * self.inverse(r) * pk_H[power] # divided by gamma, so index is smaller

        Hp_iS = Hp_iS - prod * pk_O[3]

        K = pow(self.pairing.e(Hp_iS, C1) * self.pairing.e(C2, sk_ID), exponent)

        return K

    def KeyUpdate(self, pk, r_old, r_new, sk_ID):
        pk_O, pk_H = pk

        sk_upd = r_old * self.inverse(r_new) * sk_ID

        for i, H_i in enumerate(pk_H):
            pk_H[i] = r_new * self.inverse(r_old) * H_i

        return sk_upd

    def randint(self):
        return randint(1, self.pairing.r - 1)

    def inverse(self, a: int):
        return pow(a, -1, self.pairing.r)

    def hash_mod(self, number: int): # return hash of number modulo r
        number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

        sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

        return int(sha3_384_hash, 16) % self.pairing.r


def FS_IBBE_Del7_usage_example(number_of_users: int=10):
    ibbe = FS_IBBE_Del7()

    msk, pk = ibbe.Setup(number_of_users=number_of_users)

    # S = [2, 5, 6, 37, 57, 34, 65]
    S = [i for i in range(10)]
    
    presk_IDs = []
    for ID in S:
        presk_ID = ibbe.Extract(msk=msk, ID=ID)
        presk_IDs.append(presk_ID)

    random_values = [ibbe.randint() for _ in range(len(S))]

    secret_keys = []
    for i, ID in enumerate(S):
        sk = ibbe.KeyGen(r=random_values[i], pk=pk, presk_ID=presk_IDs[i])
        secret_keys.append(sk)


    print("Encryption and Decryption example")
    user = 0
    Hdr, K = ibbe.Encrypt(S=S, pk=pk)
    K_ = ibbe.Decrypt(S=S, ID=S[user], sk_ID=secret_keys[user], Hdr=Hdr, pk=pk, r=random_values[user])

    # print("Encryption key K:", K)
    # print("")
    # print("Decryption key K':", K_)
    # print("")
    print("K == K':", K == K_)
    print("")

    print("Example with KeyUpdate usage")
    r_new = ibbe.randint()
    secret_keys[user] = ibbe.KeyUpdate(pk=pk, r_old=random_values[user], r_new=r_new, sk_ID=secret_keys[user])
    random_values[user] = r_new

    user = 0
    Hdr, K = ibbe.Encrypt(S=S, pk=pk)
    K_ = ibbe.Decrypt(S=S, ID=S[user], sk_ID=secret_keys[user], Hdr=Hdr, pk=pk, r=random_values[user])

    # print("Encryption key K:", K)
    # print("")
    # print("Decryption key K':", K_)
    # print("")
    print("K == K':", K == K_)
