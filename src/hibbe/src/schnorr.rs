use ark_bn254::{fr::Fr as ScalarField, G1Projective as G1, G2Projective as G2};
use ark_ff::{One, PrimeField};
use sha2::{Digest, Sha512};
use std::ops::{Add, Mul};

use crate::tools;

#[derive(Copy, Clone, Debug)]
pub struct SchnorrPublicKey {
    pub key: G1,
}

#[derive(Copy, Clone, Debug)]
pub struct SchnorrSecretKey {
    pub key: ScalarField,
}

#[derive(Copy, Clone, Debug)]
pub struct SchnorrSignature {
    pub left: G1,
    pub right: ScalarField,
}

#[derive(Copy, Clone, Debug)]
pub struct SchnorrIdentityProof {
    pub epk: SchnorrPublicKey,
    pub challenge: ScalarField,
    pub proof_reply: ScalarField,
}

#[derive(Copy, Clone, Debug)]
pub struct SchnorrCryptoSystem {
    pub generator: G1,
}

impl SchnorrCryptoSystem {
    pub fn new(generator: G1) -> SchnorrCryptoSystem {
        SchnorrCryptoSystem { generator }
    }

    pub fn key_gen(&self) -> (SchnorrSecretKey, SchnorrPublicKey) {
        let mut rng = rand::thread_rng();

        let sk = tools::random_non_neutral_scalar_field_element(&mut rng);
        let pk = self.generator.mul(&sk);

        (SchnorrSecretKey { key: sk }, SchnorrPublicKey { key: pk })
    }

    pub fn sign(&self, message: &Vec<u8>, sk: &SchnorrSecretKey) -> SchnorrSignature {
        let mut rng = rand::thread_rng();

        let r = tools::random_non_neutral_scalar_field_element(&mut rng);
        let left_part = self.generator.mul(&r);

        let mut hasher = Sha512::new();
        hasher.update(&message);
        hasher.update(&left_part.to_string());

        let hash = &hasher.finalize()[..];
        let hash = ScalarField::from_le_bytes_mod_order(hash);

        let right_part = r + sk.key.mul(&hash);

        SchnorrSignature {
            left: left_part,
            right: right_part,
        }
    }

    pub fn verify(
        &self,
        message: &Vec<u8>,
        signature: &SchnorrSignature,
        pk: &SchnorrPublicKey,
    ) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(&message);
        hasher.update(&signature.left.to_string());

        let hash = &hasher.finalize()[..];
        let hash = ScalarField::from_le_bytes_mod_order(hash);

        let left_part = self.generator.mul(signature.right);
        let right_part = signature.left.add(&pk.key.mul(&hash));

        left_part == right_part
    }

    pub fn initialize_interactive_identification_protocol(
        &self,
    ) -> (SchnorrSecretKey, SchnorrPublicKey) {
        self.key_gen()
    }

    pub fn gen_challenge(&self) -> ScalarField {
        tools::random_non_neutral_scalar_field_element(&mut rand::thread_rng())
    }

    pub fn gen_interactive_identity_proof(
        &self,
        challenge: &ScalarField,
        esk: &SchnorrSecretKey,
        epk: &SchnorrPublicKey,
        sk: &SchnorrSecretKey,
    ) -> SchnorrIdentityProof {
        let proof_reply = esk.key.add(sk.key.mul(challenge));
        let i = 6;

        SchnorrIdentityProof {
            epk: epk.clone(),
            challenge: challenge.clone(),
            proof_reply,
        }
    }

    pub fn verify_interactive_identity_proof(
        &self,
        proof: &SchnorrIdentityProof,
        pk: &SchnorrPublicKey,
    ) -> bool {
        let left_part = self.generator.mul(&proof.proof_reply);
        let right_part = proof.epk.key.add(pk.key.mul(&proof.challenge));

        left_part == right_part
    }

    pub fn gen_non_interactive_identity_proof(
        &self,
        sk: &SchnorrSecretKey,
        pk: &SchnorrPublicKey,
    ) -> SchnorrIdentityProof {
        let (esk, epk) = self.initialize_interactive_identification_protocol();

        let mut hasher = Sha512::new();
        hasher.update(&self.generator.to_string());
        hasher.update(&pk.key.to_string());
        hasher.update(&epk.key.to_string());
        let hash = &hasher.finalize()[..];
        let challenge = ScalarField::from_le_bytes_mod_order(hash);

        let proof_reply = esk.key.add(sk.key.mul(challenge));
        let i = 6;

        SchnorrIdentityProof {
            epk: epk.clone(),
            challenge: challenge.clone(),
            proof_reply,
        }
    }

    pub fn verify_non_interactive_identity_proof(
        &self,
        proof: &SchnorrIdentityProof,
        pk: &SchnorrPublicKey,
    ) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(&self.generator.to_string());
        hasher.update(&pk.key.to_string());
        hasher.update(&proof.epk.key.to_string());
        let hash = &hasher.finalize()[..];
        let challenge = ScalarField::from_le_bytes_mod_order(hash);

        if challenge != proof.challenge {
            return false;
        }

        let left_part = self.generator.mul(&proof.proof_reply);
        let right_part = proof.epk.key.add(pk.key.mul(&proof.challenge));

        left_part == right_part
    }
}
