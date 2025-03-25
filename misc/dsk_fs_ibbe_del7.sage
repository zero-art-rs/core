# Forward Secure IBBE protocol baseed on Cecile Delerablee (2007)
# This is the second approach to acieve Forward secrecy

import hashlib

load('./bn381.sage')

class FS_IBBE_Del7:
    def __init__(self):
        self.pairing = BN381Pairing()

        self.PollyRing = PolynomialRing(GF(self.pairing.r), "x")

    def Setup(self, number_of_users: int):        
        gamma = self.randint()
        epsilon = self.randint()

        H1 = self.randint() * self.pairing.P1
        G1 = self.randint() * self.pairing.P2

        iso1 = self.pairing.E2.isomorphism_to(self.pairing.E1)
        H2 = self.randint() * iso1(G1)

        iso2 = self.pairing.E1.isomorphism_to(self.pairing.E2)
        G2 = self.randint() * iso2(H1)

        msk = (G1, G2, gamma, epsilon)

        # Public key will consist of three logicaly separate parts
        # The next are paramethers which exists in one instance
        pk_O = {
            "w": gamma * (G1 + G2),
            "v1": self.pairing.e(H1, G1),
            "H1": H1,
            "egH2": epsilon * gamma * H2,
            "ggH2": gamma * gamma * H2,
            "gamma": gamma,
        }

        # Compute set (gamma^j) H to pk, for j in [0, number_of_users]
        pk_H = [H1]
        temp = H1
        for i in range(number_of_users):
            temp = gamma * temp
            pk_H.append(temp)

        # Compute R_i values
        pk_R = [H2 for _ in range(number_of_users)]

        pk = (pk_O, pk_H, pk_R)

        return msk, pk

    def Extract(self, msk, ID: int):
        G1, G2, gamma, epsilon = msk

        presk_1 = self.inverse(gamma + self.hash_mod(ID)) * G1
        presk_2 = self.inverse(gamma + epsilon) * G2

        return (presk_1, presk_2)

    def KeyGen(self, S, ID, r, pk, presk):
        presk1, presk2 = presk
        pk_O, pk_H, pk_R = pk

        alpha = self.randint()

        coeff = r * self.inverse(alpha)

        pk_O["egH2"] = coeff * pk_O["egH2"]
        pk_O["ggH2"] = coeff * pk_O["ggH2"]

        for i, R_i in enumerate(pk_R):
            if S[i] == ID:
                pk_R[i] = r *  R_i
            else:
                pk_R[i] = coeff *  R_i

        sk2 = alpha * self.inverse(r) * presk2

        return (presk1, sk2, r)

    def Encrypt(self, S: list[int], pk):
        k = self.randint()

        pk_O, pk_H, pk_R = pk

        C1 = -k * pk_O["w"]

        # Compute mul_polly, for which, having gamma as x, mul_poolly H = C2
        mul_polly = self.PollyRing(1)
        for ID in S:
            mul_polly *= self.PollyRing(x + self.hash_mod(ID))
        
        mul_polly = self.PollyRing(k) * mul_polly

        # Compute C2 using coefficients in polynomial mul_polly
        C2 = 0
        for power, coeff in mul_polly.monomial_coefficients().items():
            C2 += coeff * pk_H[power]

        C2 = C2 + k * (pk_O["egH2"] + pk_O["ggH2"])

        K = pow(pk_O["v1"], k)

        return (C1, C2), K

    def Decrypt(self, S, ID, sk, Hdr, pk):
        sk_1, sk_2, r = sk
        C1, C2 = Hdr
        pk_O, pk_H, pk_R = pk

        # Using polynomial p_iS_polly we will compute H^(p_iS) 
        p_iS_polly = self.PollyRing(1)
        for ID_i in S:
            if ID_i != ID:
                p_iS_polly *= self.PollyRing(x + self.hash_mod(ID_i))
        
        # remove product of Hash(ID, self.pairing.r)
        prod = 1
        for ID_i in S:
            if ID_i != ID:
                prod *= self.hash_mod(ID_i) % self.pairing.r
        
        p_iS_polly -= prod
        
        # Compute H^(p_iS) using coefficients in polynomial p_iS_polly
        Hp_iS = 0
        for power, coeff in p_iS_polly.monomial_coefficients().items():
            Hp_iS += coeff * pk_H[power - 1] # divided by gamma, so index is smaller

        Hp_iS += self.inverse(r) * pk_R[ID]
     
        K = self.pairing.e(Hp_iS, C1) * self.pairing.e(C2, sk_1 + sk_2)
        K = pow(K, self.inverse(prod))

        return K

    def KeyUpdate(self, S, ID, pk, r_new, sk):
        alpha = self.randint()

        sk1, sk2, r_old = sk
        pk_O, pk_H, pk_R = pk

        coeff = r_new * self.inverse(r_old) * self.inverse(alpha) # reuse optimisation
        for i, R_i in enumerate(pk_R):
            if S[i] == ID:
                pk_R[i] = r_new * self.inverse(r_old) * R_i
            else:
                pk_R[i] = coeff * R_i

        pk_O["egH2"] = coeff * pk_O["egH2"]
        pk_O["ggH2"] = coeff * pk_O["ggH2"]

        sk2_new = r_old * alpha * self.inverse(r_new) * sk2

        return (sk1, sk2_new, r_new)

    def randint(self) -> int:
        return randint(1, self.pairing.r - 1)

    def inverse(self, a: int) -> int:
        return pow(a, -1, self.pairing.r)

    def hash_mod(self, number: int) -> int: # return hash of number modulo r
        number_bytes = number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')

        sha3_384_hash = hashlib.sha3_384(number_bytes).hexdigest()

        return int(sha3_384_hash, 16) % self.pairing.r


def example(number_of_users: int=10):
    ibbe = FS_IBBE_Del7()

    msk, pk = ibbe.Setup(number_of_users=number_of_users)

    S = [i for i in range(number_of_users)]
    
    presk_store = []
    for ID in S:
        presk = ibbe.Extract(msk=msk, ID=ID)
        presk_store.append(presk)

    r_store = [ibbe.randint() for _ in range(len(S))]

    sk_store = []
    for i, ID in enumerate(S):
        sk = ibbe.KeyGen(r=r_store[i], S=S, ID=ID, pk=pk, presk=presk_store[i])
        sk_store.append(sk)

    print("> Encryption and Decryption example")
    user = 0
    Hdr, K = ibbe.Encrypt(S=S, pk=pk)
    K_ = ibbe.Decrypt(S=S, ID=user, sk=sk_store[user], Hdr=Hdr, pk=pk)

    print("Encryption key K:", K)
    print("")
    print("Decryption key K':", K_)
    print("")
    print("K == K':", K == K_)

    print("")
    print("> Example with KeyUpdate usage")

    r_new = ibbe.randint()
    sk_store[user] = ibbe.KeyUpdate(pk=pk, r_new=r_new, sk=sk_store[user], S=S, ID=user)

    user = 0
    Hdr, K = ibbe.Encrypt(S=S, pk=pk)
    K_ = ibbe.Decrypt(S=S, ID=S[user], sk=sk_store[user], Hdr=Hdr, pk=pk)

    print("Encryption key K:", K)
    print("")
    print("Decryption key K':", K_)
    print("")
    print("K == K':", K == K_)

