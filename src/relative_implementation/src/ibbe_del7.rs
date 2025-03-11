// IBBE protocol by Cecile Delerablee (2007)
// Signature by Paulo S.L.M. Barreto et.al (2005)

use crate::tools;
use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::short_weierstrass::Projective;
use ark_ff::{BigInt, Field, Fp, Fp12, Fp256, MontBackend, PrimeField};
use ark_std::{One, UniformRand, Zero};
use num::BigUint;
use num::bigint::Sign;
use sha2::{Digest, Sha512};
use std::ops::{Add, Mul, Neg};

#[derive(Hash, Debug, Clone, Copy)]
pub struct UserIdentity {
    pub id: u32,
}

impl UserIdentity {
    pub fn hash_to_scalar_field(&self) -> Fp256<MontBackend<FrConfig, 4>> {
        tools::sha512_from_byte_vec_to_scalar_field(&self.id.to_be_bytes().to_vec())
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub w: Projective<ark_bn254::g2::Config>,
    pub v: Fp12<Fq12Config>,
    pub powers_of_h: Vec<G1Projective<Config>>,
}

impl PublicKey {
    pub fn get_h(&self) -> &G1Projective<Config> {
        // for use instead of pk.powers_of_h[0]
        &self.powers_of_h[0]
    }

    pub fn clone(&self) -> Self {
        let powers_of_h_copy = self.powers_of_h.clone();

        PublicKey {
            w: self.w,
            v: self.v,
            powers_of_h: powers_of_h_copy,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecretKey {
    pub sk: Projective<ark_bn254::g2::Config>,
}

#[derive(Debug, Clone, Copy)]
pub struct MasterSecretKey {
    pub g: G2Projective<Config>,
    pub gamma: ScalarField,
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub c1: Projective<ark_bn254::g2::Config>,
    pub c2: Projective<ark_bn254::g1::Config>,
}

#[derive(Debug, Clone, Copy)]
pub struct EncryptionKey {
    pub key: Fp12<Fq12Config>,
}

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub hash: Fp256<MontBackend<FrConfig, 4>>,
    pub s: Projective<ark_bn254::g2::Config>,
}

#[derive(Debug)]
pub struct IBBEDel7 {
    pub pk: PublicKey,
    pub msk: Option<MasterSecretKey>,
}

impl IBBEDel7 {
    pub fn setup(max_number_of_users: u32) -> Self {
        let mut rng = ark_std::rand::thread_rng();

        let gamma = tools::random_non_neutral_scalar_field_element(&mut rng);

        let g = G2::rand(&mut rng);
        let h = G1::rand(&mut rng);

        let msk = MasterSecretKey { g, gamma };

        let w = g.mul(gamma);
        let v = Bn254::pairing(h, g).0;

        let mut powers_of_h = vec![h];
        let mut power_of_h = h;
        for _ in 0..max_number_of_users {
            power_of_h = power_of_h * gamma;
            powers_of_h.push(power_of_h);
        }

        let pk = PublicKey { w, v, powers_of_h };

        return IBBEDel7 { pk, msk: Some(msk) };
    }

    pub fn from(pk: PublicKey) -> Self {
        IBBEDel7 { pk, msk: None }
    }

    pub fn extract(&self, user: &UserIdentity) -> Result<SecretKey, String> {
        match &self.msk {
            Some(msk) => {
                // sk_id = (gamma + hash(ID))^{-1} * G
                let sk_id_hash = user.hash_to_scalar_field();
                let sk_id = msk.gamma.add(&sk_id_hash).inverse().unwrap();

                Ok(SecretKey {
                    sk: msk.g.mul(sk_id),
                })
            }
            None => Err("MasterSecretKey is unknown".to_string()),
        }
    }

    pub fn encrypt(&self, legitimate_users: &Vec<UserIdentity>) -> (Header, EncryptionKey) {
        let mut rng = rand::thread_rng();

        let k = tools::random_non_neutral_scalar_field_element(&mut rng);
        let c1 = self.pk.w.mul(-k);

        // compute c2
        let mut id_hashes = Vec::new();
        for user in legitimate_users {
            id_hashes.push(user.hash_to_scalar_field());
        }

        let coefficients = tools::compute_polynomial_coefficients(&id_hashes);

        let mut c2 = G1::zero();
        for (power, coefficient) in coefficients.iter().enumerate() {
            c2 += self.pk.powers_of_h[power] * (k * coefficient);
        }

        let y = self.pk.v;
        let k_value = BigInt::from(k);
        let key = y.pow(&k_value);

        (Header { c1, c2 }, EncryptionKey { key })
    }

    pub fn decrypt(
        &self,
        legitimate_users: &Vec<UserIdentity>,
        user_id: &UserIdentity,
        sk_id: &SecretKey,
        hdr: &Header,
    ) -> EncryptionKey {
        let mut exponent = ScalarField::one();
        for user in legitimate_users {
            if user.id.ne(&user_id.id) {
                let id_hash = user.hash_to_scalar_field();
                exponent = exponent * id_hash;
            }
        }
        exponent = exponent.inverse().unwrap();
        let exponent = BigInt::from(exponent);

        let mut id_hashes = Vec::new();
        for user in legitimate_users {
            if user_id.id.ne(&user.id) {
                id_hashes.push(user.hash_to_scalar_field());
            }
        }

        let mut coefficients = tools::compute_polynomial_coefficients(&id_hashes);
        coefficients.remove(0);

        let mut left_part = G1::zero();
        for (power, coefficient) in coefficients.iter().enumerate() {
            left_part += self.pk.powers_of_h[power] * coefficient;
        }

        let left_pairing = Bn254::pairing(left_part, hdr.c1).0;
        let right_pairing = Bn254::pairing(hdr.c2, sk_id.sk).0;
        let key = (left_pairing * right_pairing).pow(exponent);

        EncryptionKey { key }
    }

    pub fn sign(&self, message: &String, sk_id: &SecretKey) -> Signature {
        let mut rng = ark_std::rand::thread_rng();
        let x = tools::random_non_neutral_scalar_field_element(&mut rng);
        let r = self.pk.v.pow(&x.into_bigint());

        let mut message_as_bytes = message.as_bytes().to_vec();
        message_as_bytes.append(&mut r.to_string().into_bytes());
        let hash = tools::sha512_from_byte_vec_to_scalar_field(&message_as_bytes);

        let s = sk_id.sk.mul(x + hash);

        Signature { hash, s }
    }

    pub fn verify(&self, message: &String, sigma: &Signature, user: &UserIdentity) -> bool {
        let id_hash = user.hash_to_scalar_field();

        let neg_hash = sigma.hash.neg();
        let mut right_part = Bn254::pairing(
            self.pk.powers_of_h[0].mul(id_hash) + self.pk.powers_of_h[1],
            sigma.s,
        )
        .0;

        right_part *= self.pk.v.pow(&neg_hash.into_bigint());

        let mut message_as_bytes = message.as_bytes().to_vec();
        message_as_bytes.append(&mut right_part.to_string().into_bytes());

        sigma.hash.eq(&tools::sha512_from_byte_vec_to_scalar_field(
            &message_as_bytes,
        ))
    }
}
