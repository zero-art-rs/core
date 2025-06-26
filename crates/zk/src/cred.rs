#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{self, Instant, SystemTime};

use rand_core::{le, OsRng};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use bulletproofs::{r1cs::*, ProofError};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{self, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use tracing_subscriber::field::debug;
use zkp::toolbox::dalek_ark::ark_to_scalar;
use zkp::toolbox::{FromBytes, SchnorrCS, ToBytes};
use zkp::BatchableProof;
use crate::art::R1CSProof;
use crate::curve::cortado::{self, CortadoAffine, FromScalar, Parameters, ToScalar};
use crate::dh::scalar_mul_gadget_v2;
use crate::gadgets;
use crate::gadgets::poseidon_gadget::{PoseidonParams, Poseidon_hash_4, Poseidon_hash_8, Poseidon_hash_8_constraints, Poseidon_hash_8_gadget, SboxType};
use crate::gadgets::r1cs_utils::{AllocatedPoint, AllocatedScalar};
use hex::FromHex;
use zkp::toolbox::prover::Prover;
use zkp::toolbox::verifier::Verifier;

fn get_poseidon_params() -> PoseidonParams{
    let width = 10;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    PoseidonParams::new(width, full_b, full_e, partial_rounds)
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialClaims {
    id: cortado::Fq, // credential unique identifier (seed)
    Q: CortadoAffine, // credential holder public key
    expiration: u64, // credential expiration time as UNIX timestamp
}

impl ToBytes for CredentialClaims {}
impl FromBytes for CredentialClaims {}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: (CortadoAffine, cortado::Fr),
    pub issuer: CortadoAffine, // issuer public key
}

impl Credential {
    fn sign_claims(
        claims: &CredentialClaims,
        secret_key: cortado::Fr,
    ) -> Result<(CortadoAffine, CortadoAffine, cortado::Fr), R1CSError> {
        let Q = (CortadoAffine::generator() * secret_key).into_affine();
        let r = cortado::Fr::rand(&mut rand::thread_rng());
        let R = (CortadoAffine::generator() * r).into_affine();
        let hash = Poseidon_hash_8(
            [
                claims.id.into_scalar(), 
                claims.Q.x().unwrap().into_scalar(), 
                claims.Q.y().unwrap().into_scalar(), 
                cortado::Fq::from(claims.expiration).into_scalar(),
                Q.x().unwrap().into_scalar(),
                Q.y().unwrap().into_scalar(),
                R.x().unwrap().into_scalar(),
                R.y().unwrap().into_scalar()
                ], 
            &get_poseidon_params(), 
            &SboxType::Penta
        );
        let s = secret_key * cortado::Fr::from_le_bytes_mod_order(hash.as_bytes()) + r;
        
        Ok((Q, R, s))
    }

    /// issue new credential
    pub fn issue(issuer: cortado::Fr, expiration: SystemTime, holder: CortadoAffine) -> Result<Self, R1CSError> {
        let claims = CredentialClaims {
            id: cortado::Fq::rand(&mut rand::thread_rng()), // This should be a unique identifier, e.g., a hash of the holder's public key
            Q: holder,
            expiration: expiration
                .duration_since(time::UNIX_EPOCH)
                .expect("expiration must be after UNIX_EPOCH")
                .as_secs(),
        };
        let (Q, R, s) = Self::sign_claims(&claims, issuer)
            .map_err(|_| R1CSError::FormatError)?;
        Ok(Self {
            claims,
            signature: (R, s),
            issuer: Q,
        })
    }

    /// verify loaded credential (only for holder)
    pub fn verify(&self) -> Result<(), R1CSError> {
        let hash = Poseidon_hash_8(
            [
                self.claims.id.into_scalar(), 
                self.claims.Q.x().unwrap().into_scalar(), 
                self.claims.Q.y().unwrap().into_scalar(), 
                cortado::Fq::from(self.claims.expiration).into_scalar(),
                self.issuer.x().unwrap().into_scalar(),
                self.issuer.y().unwrap().into_scalar(),
                self.signature.0.x().unwrap().into_scalar(),
                self.signature.0.y().unwrap().into_scalar(),
            ], 
            &get_poseidon_params(), 
            &SboxType::Penta
        );

        let R2 = (CortadoAffine::generator() * self.signature.1 - self.issuer * cortado::Fr::from_le_bytes_mod_order(hash.as_bytes())).into_affine();
        if self.signature.0 == R2 {
            Ok(())
        } else {
            Err(R1CSError::VerificationError)
        }
    }

    /// create credential presentation proof
    pub fn present(&self) -> Result<R1CSProof, R1CSError> {
        todo!()
    }
}

pub fn credential_presentation_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    poseidon_statics: Vec<AllocatedScalar>,
    id: AllocatedScalar,
    Q_holder: AllocatedPoint,
    expiration: AllocatedScalar,
    Q_issuer: AllocatedPoint, // public input
    c: AllocatedScalar,
    R: AllocatedPoint,
    s: AllocatedScalar,
) -> Result<(), R1CSError> {

    let input = [
        LinearCombination::from(id.variable), 
        LinearCombination::from(Q_holder.x.variable), 
        LinearCombination::from(Q_holder.y.variable), 
        LinearCombination::from(expiration.variable), 
        LinearCombination::from(Q_issuer.x.variable), 
        LinearCombination::from(Q_issuer.y.variable),
        LinearCombination::from(R.x.variable), 
        LinearCombination::from(R.y.variable),
    ];
    
    let hash_lc = Poseidon_hash_8_constraints(cs, input, poseidon_statics.iter().map(|x| LinearCombination::from(x.variable)).collect(), &get_poseidon_params(), &SboxType::Penta)?;
    cs.constrain(c.variable - hash_lc);
    todo!()
    //scalar_mul_gadget_v2(cs, c, Q_b)
}

#[test]
fn test_credential_issue() {
    let claims = CredentialClaims {
        id: cortado::Fq::from(1234567890u64),
        Q: CortadoAffine::generator(),
        expiration: SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("time must be after UNIX_EPOCH")
            .as_secs(),
    };
    let secret_key = rand::thread_rng().r#gen::<cortado::Fr>();
    Credential::sign_claims(&claims, secret_key);
}