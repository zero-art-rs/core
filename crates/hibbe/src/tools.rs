use crate::ibbe_del7::{IBBEDel7, SecretKey, UserIdentity};
use crate::tools;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use ark_bn254::fr::Fr as ScalarField;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::iterable::Iterable;
use ark_std::{One, UniformRand, Zero};
use hkdf::Hkdf;
use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
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
pub fn sha512_from_bytes(bytes: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hasher.finalize()[..].to_vec()
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

// For serialisation
pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::No)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

// For deserialization
pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::No, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

pub fn gen_ibbe_tool_box(group_size: u32) -> (IBBEDel7, Vec<UserIdentity<String>>) {
    let ibbe = IBBEDel7::setup(group_size);
    let members = crete_set_of_identities(group_size);

    (ibbe, members)
}

pub struct UserSample<T> {
    pub index: usize,
    pub identity: UserIdentity<T>,
    pub sk_id: SecretKey,
}
pub fn get_subset_of_user_identities<T: Into<Vec<u8>> + Clone + PartialEq>(
    number_of_users: usize,
    ibbe: &IBBEDel7,
    members: &Vec<UserIdentity<T>>,
) -> Result<Vec<UserSample<T>>, String> {
    if number_of_users > members.len() {
        return Err(format!(
            "Not enough elements in a given set: try to get {} users from {}-user set",
            number_of_users,
            members.len()
        ));
    }

    let mut users_set = Vec::new();

    let mut numbers: Vec<usize> = (0..members.len()).into_iter().collect();
    numbers.shuffle(&mut rand::thread_rng());
    let usable_numbers = numbers[0..number_of_users].to_vec();

    for index in usable_numbers {
        let identity = members[index].clone();
        let sk_id = ibbe.extract(&identity)?;

        users_set.push(UserSample {
            index,
            identity,
            sk_id,
        });
    }

    Ok(users_set)
}

pub fn sample_user_identity<T: Into<Vec<u8>> + Clone + PartialEq>(
    ibbe: &IBBEDel7,
    members: &Vec<UserIdentity<T>>,
) -> (usize, UserIdentity<T>, SecretKey) {
    let sample = get_subset_of_user_identities(1, ibbe, members)
        .unwrap()
        .pop()
        .unwrap();

    (sample.index, sample.identity.clone(), sample.sk_id)
}

pub fn gen_random_string(message_size: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(message_size)
        .map(char::from)
        .collect()
}
