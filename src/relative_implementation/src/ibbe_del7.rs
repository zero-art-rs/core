use num::BigUint;
use sha2::{Digest, Sha512};
// use std::hash::Hash;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Field, Fp, Fp12, Fp256, MontBackend};
use ark_std::{One, UniformRand, Zero};
use std::ops::{Add, Mul};

use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::short_weierstrass::Projective;
use rand::Rng;

#[derive(Debug)]
pub struct IBBEDel7 {}

impl IBBEDel7 {
    // return random ScalarField element, which isn't zero or one
    fn random_non_neutral_scalar_field_element<R: Rng + ?Sized>(
        rng: &mut R,
    ) -> Fp256<MontBackend<FrConfig, 4>> {
        let mut k = ScalarField::zero();
        while k.eq(&ScalarField::one()) || k.eq(&ScalarField::zero()) {
            k = ScalarField::rand(rng);
        }

        k
    }
    pub fn run_setup(
        max_number_of_users: u32,
    ) -> (
        (G2Projective<Config>, Fp256<MontBackend<FrConfig, 4>>),
        (
            ark_ec::short_weierstrass::Projective<ark_bn254::g2::Config>,
            PairingOutput<Bn<Config>>,
            G1Projective<Config>,
            Vec<G1Projective<Config>>,
        ),
    ) {
        let mut rng = ark_std::test_rng();

        let gamma = IBBEDel7::random_non_neutral_scalar_field_element(&mut rng);

        let g = G2::rand(&mut rng);
        let h = G1::rand(&mut rng);

        let msk = (g, gamma);

        let w = g.mul(gamma);
        let v = Bn254::pairing(h, g);

        let mut powers_of_h = vec![h];
        let mut power_of_h = h;
        for _ in 1..max_number_of_users {
            power_of_h = power_of_h * gamma;
            powers_of_h.push(power_of_h);
        }

        let pk = (w, v, h, powers_of_h);

        return (msk, pk);
    }

    // compute hash, and convert to ScalarField
    fn sha512_from_u32_to_scalar_field(number: u32) -> Fp256<MontBackend<FrConfig, 4>> {
        let mut hasher = Sha512::new();
        hasher.update(number.to_be_bytes());
        let number_hash = &hasher.finalize()[..];
        let number_hash = BigUint::from_bytes_le(number_hash);
        ScalarField::from(number_hash)
    }

    pub fn extract(
        msk: &(G2Projective<Config>, ScalarField),
        id: u32,
    ) -> ark_ec::short_weierstrass::Projective<ark_bn254::g2::Config> {
        let (g, gamma) = &msk;

        // sk_id = (gamma + hash(ID))^{-1} * G
        let sk_id_hash = IBBEDel7::sha512_from_u32_to_scalar_field(id);
        let sk_id = gamma.add(&sk_id_hash).inverse().unwrap();
        g.mul(sk_id)
    }

    fn compute_polynomial_coefficients(roots: &Vec<ScalarField>) -> Vec<ScalarField> {
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

    pub fn encrypt(
        legitimate_users: &Vec<u32>,
        pk: &(
            Projective<ark_bn254::g2::Config>,
            PairingOutput<Bn<Config>>,
            G1Projective<Config>,
            Vec<G1Projective<Config>>,
        ),
    ) -> (
        (
            Projective<ark_bn254::g2::Config>,
            Projective<ark_bn254::g1::Config>,
        ),
        Fp12<Fq12Config>,
    ) {
        let (w, v, _, powers_of_h) = pk;

        let mut rng = ark_std::test_rng();

        let k = IBBEDel7::random_non_neutral_scalar_field_element(&mut rng);
        let c1 = w.mul(-k);

        // compute c2
        let mut id_hashes = Vec::new();
        for id in legitimate_users {
            id_hashes.push(IBBEDel7::sha512_from_u32_to_scalar_field(*id));
        }

        let coefficients = IBBEDel7::compute_polynomial_coefficients(&id_hashes);

        let mut c2 = G1::zero();
        for (power, coefficient) in coefficients.iter().enumerate() {
            c2 += powers_of_h[power] * (k * coefficient);
        }

        let y = v.0;
        let k_value = BigInt::from(k);
        let key = y.pow(&k_value);

        ((c1, c2), key)
    }

    pub fn decrypt(
        legitimate_users: &Vec<u32>,
        user_id: u32,
        sk_id: &Projective<ark_bn254::g2::Config>,
        hdr: &(
            Projective<ark_bn254::g2::Config>,
            Projective<ark_bn254::g1::Config>,
        ),
        pk: &(
            ark_ec::short_weierstrass::Projective<ark_bn254::g2::Config>,
            PairingOutput<Bn<Config>>,
            G1Projective<Config>,
            Vec<G1Projective<Config>>,
        ),
    ) -> Fp12<Fq12Config> {
        let (c1, c2) = hdr;
        let (_, _, _, powers_of_h) = pk;

        let mut exponent = ScalarField::one();
        for id in legitimate_users {
            if id.ne(&user_id) {
                let id_hash = IBBEDel7::sha512_from_u32_to_scalar_field(*id);
                exponent = exponent * id_hash;
            }
        }
        exponent = exponent.inverse().unwrap();
        let exponent = BigInt::from(exponent);

        let mut id_hashes = Vec::new();
        for id in legitimate_users {
            if user_id.ne(&id) {
                id_hashes.push(IBBEDel7::sha512_from_u32_to_scalar_field(*id));
            }
        }

        let mut coefficients = IBBEDel7::compute_polynomial_coefficients(&id_hashes);
        coefficients.remove(0);

        let mut left_part = G1::zero();
        for (power, coefficient) in coefficients.iter().enumerate() {
            left_part += powers_of_h[power] * coefficient;
        }

        let left_pairing = Bn254::pairing(left_part, c1).0;
        let right_pairing = Bn254::pairing(c2, sk_id).0;
        let key = (left_pairing * right_pairing).pow(exponent);

        key
    }
}
