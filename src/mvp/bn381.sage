class BN381Pairing:
    def __init__(self):
        BN381_1 = {
            "p": 0x240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908f41c8020ffffffffff6ff66fc6ff687f640000000002401b00840138013,
            "r": 0x240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908ee1c201f7fffffffff6ff66fc7bf717f7c0000000002401b007e010800d,
            "P": (0x21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d, 
                  0x0118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de),
            "b": 5
        }
        Fp = GF(BN381_1["p"])

        E0 = EllipticCurve(Fp, [0,BN381_1["b"]])
        E0.set_order(BN381_1["r"])

        Fp12.<x> = GF(BN381_1["p"]^12)
        RF.<T> = PolynomialRing(Fp12)
        i = (T^2 + 1).roots(ring=Fp12, multiplicities=0)[0]

        BN381_2 = {
            "P": (0x0257ccc85b58dda0dfb38e3a8cbdc5482e0337e7c1cd96ed61c913820408208f9ad2699bad92e0032ae1f0aa6a8b48807695468e3d934ae1e4df+
          0x1d2e4343e8599102af8edca849566ba3c98e2a354730cbed9176884058b18134dd86bae555b783718f50af8b59bf7e850e9b73108ba6aa8cd283*i, 
          0x0a0650439da22c1979517427a20809eca035634706e23c3fa7a6bb42fe810f1399a1f41c9ddae32e03695a140e7b11d7c3376e5b68df0db7154e+
          0x073ef0cbd438cbe0172c8ae37306324d44d5e6b0c69ac57b393f1ab370fd725cc647692444a04ef87387aa68d53743493b9eba14cc552ca2a93a*i),
            "b": -i+2
        }
        self.r = BN381_1["r"]
        self.E1 = EllipticCurve(Fp12, [0,BN381_1["b"]])
        self.E2 = EllipticCurve(Fp12, [0,BN381_2["b"]])
        self.phi = self.E2.isomorphism_to(self.E1)


        self.P1=self.E1(BN381_1["P"])
        self.P2=self.E2(BN381_2["P"])
        
    def e(self, P, Q):
        return P.tate_pairing(self.phi(Q), self.r, k=12)

def test():
    pe = BN381Pairing()
    print(pe.e(pe.P1, pe.P2))