// Unfortunately, arkworks has a bug for primes p=8k+5, tests run infinitely
/*
use crate::{fq::Fq, fr::Fr, cortado::CortadoProjective};
use ark_algebra_test_templates::{test_field, test_group};

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
test_group!(g2; CortadoProjective);
*/

/// `ALT_GENERATOR` is derived from a public seed, so nobody knows its discrete log with respect
/// to the generator.
#[cfg(test)]
mod alt_generator {
    use crate::{ALT_GENERATOR_X, ALT_GENERATOR_Y, CortadoAffine, Fq, Parameters};
    use ark_ec::{AffineRepr, short_weierstrass::SWCurveConfig};
    use ark_ff::{BigInt, BigInteger, Field, PrimeField};
    use sha2::{Digest, Sha256};

    /// The seed of the alternative generator.
    const SEED: &[u8] = b"zero-art/cortado/alt-generator/v1";

    /// A square root of `a` in Fq, whose modulus is 5 mod 8 (Atkin's algorithm), or `None` when
    /// `a` is not a square. Avoids `Field::sqrt`, see the note at the top of this file.
    fn sqrt_5_mod_8(a: Fq) -> Option<Fq> {
        // (q - 5) / 8
        let mut e = Fq::MODULUS;
        e.sub_with_borrow(&BigInt::from(5u64));
        e.divn(3);
        let two_a = a + a;
        let v = two_a.pow(e);
        let i = two_a * v.square();
        let root = a * v * (i - Fq::ONE);
        (root.square() == a).then_some(root)
    }

    /// The first x = SHA-256(SEED ‖ counter as 4 bytes, little-endian) mod q, counter = 0, 1, ...,
    /// for which x^3 + a·x + b is a square, and y its square root whose integer is even. The
    /// cofactor is 1, so (x, y) generates the whole group.
    fn derive() -> (Fq, Fq, u32) {
        for counter in 0u32.. {
            let digest = Sha256::new()
                .chain_update(SEED)
                .chain_update(counter.to_le_bytes())
                .finalize();
            let x = Fq::from_le_bytes_mod_order(&digest[..]);
            let rhs = x.square() * x + Parameters::COEFF_A * x + Parameters::COEFF_B;
            if let Some(y) = sqrt_5_mod_8(rhs) {
                let y = if y.into_bigint().is_even() { y } else { -y };
                return (x, y, counter);
            }
        }
        unreachable!("a square is found within a few tries")
    }

    #[test]
    fn alt_generator_is_derived_from_the_seed() {
        let (x, y, counter) = derive();
        println!("ALT_GENERATOR from counter {counter}:\nx = {x}\ny = {y}");
        assert_eq!(ALT_GENERATOR_X, x);
        assert_eq!(ALT_GENERATOR_Y, y);

        let h = CortadoAffine::new(x, y);
        assert!(h.is_on_curve());
        assert_ne!(h, CortadoAffine::generator());
    }
}
