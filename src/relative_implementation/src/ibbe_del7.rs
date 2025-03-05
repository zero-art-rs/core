use num::BigUint;
use sha2::{Digest, Sha256, Sha512};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::Saturating;
use std::process::{Command, ExitStatus};

use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{BigInt, Field, Fp, Fp256, MontBackend};
use ark_std::{One, UniformRand, Zero};

// use ark_test_curves::bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, Fq12 as Fq12};
// use ark_test_curves::bls12_381::Fr as ScalarField;
// use ark_algebra_bench_templates::*;

use ark_bn254::{
    Bn254, Config, Fq12, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use rand::Rng;
// use ark_ec::twisted_edwards::Projective;
// use sha2::digest::Output;

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

        let w = g * gamma;
        let v = Bn254::pairing(h, g);

        let mut powers_of_h = vec![h];
        let mut power_of_h = h;
        for i in 1..max_number_of_users {
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
        msk: (G2Projective<Config>, ScalarField),
        id: u32,
    ) -> ark_ec::short_weierstrass::Projective<ark_bn254::g2::Config> {
        let (g, gamma): (G2Projective<Config>, ScalarField) = msk;

        // sk_id = (gamma + hash(ID))^{-1} * G
        let sk_id_hash = IBBEDel7::sha512_from_u32_to_scalar_field(id);
        let sk_id: ScalarField = gamma + sk_id_hash;
        let sk_id: ScalarField = Fp256::inverse(&sk_id).unwrap();
        g * sk_id
    }
}
