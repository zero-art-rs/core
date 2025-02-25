# Curve based on https://crypto.stanford.edu/~dabo/papers/2dnf.pdf

class PQL256Pairing:
    def __init__(self):
        # Precomputed dictionary of paramethers, where n1 and n2 are of bit size 100
        PQL256 = {
            'n1': 1208014676886436879837195513400243,
            'n2': 1145778175710023927443110899750543,
            'n': 1384116852713875655724384689308561674553538330299457454762415581949,
            'l': 6,
            'p': 8304701116283253934346308135851370047321229981796744728574493491693
        }

        self.n1 = PQL256["n1"]
        self.n2 = PQL256["n2"]
        self.l = PQL256["l"]
        self.p = PQL256["p"]
        self.r = PQL256["p"] + 1

        self.Fp = GF(PQL256["p"])
        self.E0 = EllipticCurve(self.Fp, [0, 1])

        Fp2.<x> = GF(PQL256["p"]^2)
        RF.<T> = PolynomialRing(Fp2)
        i = (T^2 + 1).roots(ring=Fp2, multiplicities=0)[0]

        self.E1 = EllipticCurve(Fp2, [0, 1])
        self.E2 = EllipticCurve(Fp2, [0, -i + 2])
        self.phi = self.E2.isomorphism_to(self.E1)

        self.P1 = self.E1.gen(0)
        self.P2 = self.E2.gen(0)
    
    def e(self, P, Q):
        return P.tate_pairing(self.phi(Q), self.r, k=2)

# Generates paramethers for PQL256Pairing,
# Here size is a bit size of n1 and n2
def generate_paramethers_for_curve(size: int=256):
    while True:
        n1 = random_prime(2**size, lbound=2**(size - 1))
        n2 = random_prime(2**size, lbound=2**(size - 1))
    
        n = n1 * n2
    
        for l in range(1, 8):
            p = l * n - 1
            if p.is_prime() and p % 3 == 2:
                curve_paramethers = {
                    "n1": n1,
                    "n2": n2,
                    "n": n,
                    "l": l,
                    "p": p,
                }
                return curve_paramethers

def test():
    pairing = PQL256Pairing()

    G1 = randint(1, pairing.r - 1) * pairing.n2 * pairing.l * pairing.P1
    H1 = randint(1, pairing.r - 1) * pairing.l * pairing.P2

    iso1 = pairing.E2.isomorphism_to(pairing.E1)
    G2 = randint(1, pairing.r - 1) * iso1(H1)

    iso2 = pairing.E1.isomorphism_to(pairing.E2)
    H2 = randint(1, pairing.r - 1) * iso2(G1)

    print("pairing.e(G1, H1)", pairing.e(G1, H1)) # Non neutral value
    print("pairing.e(G1, H2)", pairing.e(G1, H2)) # Neutral value
    print("pairing.e(G2, H1)", pairing.e(G2, H1)) # Neutral value
    print("pairing.e(G2, H2)", pairing.e(G2, H2)) # Non neutral value

    sk1 = randint(1, pairing.r - 1) * G1
    sk2 = randint(1, pairing.r - 1) * G2
    sk = sk1 + sk2

    #Next are the same
    print("sk^p^a: ", pow(pairing.n1, 17, pairing.p + 1) * sk)
    print("sk2^p^a:", pow(pairing.n1, 17, pairing.p + 1) * sk2)