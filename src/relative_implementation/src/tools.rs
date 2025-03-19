use crate::ibbe_del7::UserIdentity;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use ark_bn254::fr::Fr as ScalarField;
use ark_ff::PrimeField;
use ark_std::{One, UniformRand, Zero};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

// return random ScalarField element, which isn't zero or one
pub fn random_non_neutral_scalar_field_element<R: Rng + ?Sized>(rng: &mut R) -> ScalarField {
    let mut k = ScalarField::zero();
    while k.eq(&ScalarField::one()) || k.eq(&ScalarField::zero()) {
        k = ScalarField::rand(rng);
    }

    k
}

// compute hash, and convert to ScalarField
pub fn sha512_from_byte_vec_to_scalar_field(bytes: &Vec<u8>) -> ScalarField {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let bytes = &hasher.finalize()[..];
    ScalarField::from_le_bytes_mod_order(bytes)
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

pub fn encrypt_aes(key_bytes: Vec<u8>, plaintext: String) -> Result<Vec<u8>, String> {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let result = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&result[..]);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);
    let ciphered_data = cipher.encrypt(&nonce, plaintext.as_bytes());

    let ciphered_data = match ciphered_data {
        Ok(ciphered_data) => ciphered_data,
        Err(e) => return Err(String::from(format!("Failed to encrypt: {:?}", e))),
    };

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphered_data);

    Ok(encrypted_data)
}

pub fn decrypt_aes(key_bytes: Vec<u8>, encrypted_data: Vec<u8>) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    let result = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(&result[..]);
    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_arr);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphered_data);

    let plaintext = match plaintext {
        Ok(plaintext) => String::from_utf8(plaintext),
        Err(e) => return Err(String::from(format!("Failed to decrypt: {:?}", e))),
    };

    let plaintext = match plaintext {
        Ok(plaintext) => plaintext,
        Err(e) => {
            return Err(String::from(format!(
                "Failed to convert to string: {:?}",
                e
            )));
        }
    };

    Ok(plaintext)
}
