use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ff::{Fp256, MontBackend};
use ark_std::{One, UniformRand, Zero};
use num::BigUint;
use rand::Rng;

use sha2::{Digest, Sha512};
use std::ptr::hash;

// return random ScalarField element, which isn't zero or one
pub fn random_non_neutral_scalar_field_element<R: Rng + ?Sized>(
    rng: &mut R,
) -> Fp256<MontBackend<FrConfig, 4>> {
    let mut k = ScalarField::zero();
    while k.eq(&ScalarField::one()) || k.eq(&ScalarField::zero()) {
        k = ScalarField::rand(rng);
    }

    k
}

// compute hash, and convert to ScalarField
pub fn sha512_from_byte_vec_to_scalar_field(bytes: &Vec<u8>) -> Fp256<MontBackend<FrConfig, 4>> {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let hash = &hasher.finalize()[..];
    let hash = BigUint::from_bytes_le(hash);
    ScalarField::from(hash)
}

// Given a list of scalars (a0, a1, ..., an) compute coefficients of
// polynomial (x + a0)(x + a1)...(x + an)
pub fn compute_polynomial_coefficients(roots: &Vec<ScalarField>) -> Vec<ScalarField> {
    let n = roots.len();

    let mut coefs = vec![ScalarField::zero(); n + 1];
    coefs[0] = ScalarField::one();
    let mut current_degree = 0;
    for value in roots {
        coefs[current_degree + 1] = coefs[current_degree];
        for i in (1..=current_degree).rev() {
            coefs[i] = coefs[i - 1] + coefs[i] * value;
        }
        coefs[0] *= value;

        current_degree += 1;
    }

    coefs
}
