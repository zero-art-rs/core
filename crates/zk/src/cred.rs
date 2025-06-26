#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{self, Instant, SystemTime};

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
use zkp::toolbox::{FromBytes, SchnorrCS, ToBytes};
use zkp::BatchableProof;
use crate::art::R1CSProof;
use crate::curve::cortado::{self, CortadoAffine, Parameters, ToScalar};
use crate::poseidon::r1cs_utils::AllocatedScalar;
use hex::FromHex;
use zkp::toolbox::prover::Prover;
use zkp::toolbox::verifier::Verifier;

pub struct AllocatedPoint {
    pub x: AllocatedScalar,
    pub y: AllocatedScalar,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialClaims {
    id: cortado::Fr, // credential unique identifier (seed)
    Q: CortadoAffine, // credential holder public key
    expiration: u64, // credential expiration time as UNIX timestamp
}

impl ToBytes for CredentialClaims {}
impl FromBytes for CredentialClaims {}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: (CortadoAffine, cortado::Fr)
}

impl Credential {
    fn dl_statement<CS: SchnorrCS>(
        cs: &mut CS,
        x: CS::ScalarVar,
        A: CS::PointVar,
        B: CS::PointVar,
    ) {
        cs.constrain(A, vec![(x, B)]);
    }

    /// issue new credential
    pub fn issue(issuer: cortado::Fr, expiration: SystemTime, holder: CortadoAffine) -> Result<Self, R1CSError> {
        let claims = CredentialClaims {
            id: issuer,
            Q: holder,
            expiration: expiration
                .duration_since(time::UNIX_EPOCH)
                .expect("expiration must be after UNIX_EPOCH")
                .as_secs(),
        };
        let claims_bytes = claims.to_bytes().map_err(|_| R1CSError::FormatError)?;
        let mut transcript = Transcript::new(b"credential_issuance");
        transcript.append_message(b"credential", &claims_bytes);
        let mut prover = Prover::new(b"credential_issuance", transcript);
        let s_var = prover.allocate_scalar(b"s", issuer);
        let (G_var, _) = prover.allocate_point(b"G", cortado::CortadoAffine::generator());
        let Q = (cortado::CortadoAffine::generator() * issuer).into_affine();
        let (Q_var, _) = prover.allocate_point(b"Q", Q);
        Self::dl_statement(&mut prover, s_var, Q_var, G_var);
        let proof = prover.prove_batchable();
        Ok(
            Credential { claims, signature: (proof.commitments[0], proof.responses[0]) }
        )
    }

    /// verify loaded credential (only for holder)
    pub fn verify(&self) -> Result<(), R1CSError> {
        let claims_bytes = self.claims.to_bytes().map_err(|_| R1CSError::FormatError)?;
        let mut transcript = Transcript::new(b"credential_issuance");
        transcript.append_message(b"credential", &claims_bytes);
        let mut verifier = Verifier::new(b"credential_issuance", transcript);
        let s_var = verifier.allocate_scalar(b"s");
        let G_var = verifier.allocate_point(b"G", cortado::CortadoAffine::generator()).map_err(|_| R1CSError::VerificationError)?;
        let Q_var = verifier.allocate_point(b"Q", self.claims.Q).map_err(|_| R1CSError::VerificationError)?;
        Self::dl_statement(&mut verifier, s_var, Q_var, G_var);

        verifier.verify_batchable(&BatchableProof{
            commitments: vec![self.signature.0],
            responses: vec![self.signature.1],
        }).map_err(|_| R1CSError::VerificationError)
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