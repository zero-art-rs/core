use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field, Fp256, MontBackend};
use ark_std::UniformRand;

// use ark_test_curves::bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, Fq12 as Fq12};
// use ark_test_curves::bls12_381::Fr as ScalarField;
// use ark_algebra_bench_templates::*;

use ark_bn254::{
    Bn254, Config, Fq12, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField,
    fr::FrConfig
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::twisted_edwards::Projective;

#[derive(Debug)]
pub struct IBBEDel7 {}

impl IBBEDel7 {
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

        let gamma = ScalarField::rand(&mut rng);

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
}
