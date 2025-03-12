use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ff::{Fp256, MontBackend};
use ark_std::{One, UniformRand, Zero};
use num::BigUint;
use rand::Rng;
use std::convert::identity;

use crate::ibbe_del7::UserIdentity;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

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

pub fn crete_set_of_identities(number_of_users: u32) -> Vec<UserIdentity<String>> {
    let mut set_of_users = Vec::new();

    for id in 0..number_of_users {
        set_of_users.push(UserIdentity {
            identity: String::from(id.to_string()),
        });
    }

    set_of_users
}

pub fn hkdf(ikm: &Vec<u8>, salt: Option<&[u8]>, info: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha512 to output");

    okm.to_vec()
}

pub fn encrypt_aes(key_bytes: Vec<u8>, plaintext: String) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let result = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&result[..]);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);
    let ciphered_data = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("failed to encrypt");

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphered_data);
    encrypted_data
}

pub fn decrypt_aes(key_bytes: Vec<u8>, encrypted_data: Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let result = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&result[..]);
    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_arr);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphered_data)
        .expect("failed to decrypt data");
    String::from_utf8(plaintext).expect("failed to convert vector of bytes to string")
}
