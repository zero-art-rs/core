#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{self, Instant};

use rand_core::{le, OsRng};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use bulletproofs::{r1cs::*, ProofError};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use tracing_subscriber::field::debug;
use crate::art::R1CSProof;
use crate::curve::cortado::{self, CortadoAffine, Parameters, ToScalar};
use crate::poseidon::r1cs_utils::AllocatedScalar;
use hex::FromHex;

pub struct AllocatedPoint {
    pub x: AllocatedScalar,
    pub y: AllocatedScalar,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialClaims {
    id: cortado::Fr, // credential unique identifier (seed)
    Q: CortadoAffine, // credential holder public key
    expiration: u64, // credential expiration time
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: (CortadoAffine, cortado::Fr)
}

impl Credential {
    /// issue new credential
    pub fn issue(issuer: cortado::Fr, expiration: Instant, holder: CortadoAffine) -> Self {
        todo!()
    }

    /// verify loaded credential (only for holder)
    pub fn verify(&self) -> Result<(), R1CSError> {
        todo!()
    }

    /// create credential presentation proof
    pub fn present(&self) -> Result<R1CSProof, R1CSError> {
        todo!()
    }
}

pub fn credential_presentation_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    R: AllocatedPoint,
    s: AllocatedScalar,

    Q_holder: AllocatedPoint,
    Q_issuer: CortadoAffine,
    
) -> Result<(), R1CSError> {
    todo!()
}