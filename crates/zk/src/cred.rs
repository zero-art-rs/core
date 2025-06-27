#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{self, Instant, SystemTime};

use rand_core::{le, OsRng};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use bulletproofs::{r1cs::{self, *}, ProofError};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{self, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, UniformRand};
use tracing_subscriber::field::debug;
use zkp::toolbox::dalek_ark::ark_to_scalar;
use zkp::toolbox::{FromBytes, SchnorrCS, ToBytes};
use zkp::BatchableProof;
use crate::curve::cortado::{self, CortadoAffine, FromScalar, Parameters, ToScalar};
use crate::dh::{scalar_mul_gadget_v1, scalar_mul_gadget_v2};
use crate::gadgets;
use crate::gadgets::poseidon_gadget::{PoseidonParams, Poseidon_hash_4, Poseidon_hash_8, Poseidon_hash_8_constraints, Poseidon_hash_8_gadget, SboxType};
use crate::gadgets::r1cs_utils::{co_linear_gadget, AllocatedPoint, AllocatedScalar, ProversAllocatableCortado as _, VerifiersAllocatableCortado as _};
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


// TODO: implement FromBytes and ToBytes for CredentialPresentationProof
#[derive(Clone)]
pub struct CredentialPresentationProof {
    pub proof: R1CSProof,
    pub id_comm: CompressedRistretto,
    pub Q_holder_comm: (CompressedRistretto, CompressedRistretto),
    pub exp_comm: CompressedRistretto,
    pub c_comm: CompressedRistretto,
    pub R_comm: (CompressedRistretto, CompressedRistretto),
    pub s_comm: CompressedRistretto,
    pub Q_issuer: CortadoAffine, // issuer public key
}

impl Credential {
    fn get_hash(&self) -> Scalar {
        Poseidon_hash_8(
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
        )
    }

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
        debug!("{}", cortado::FqConfig::MODULUS >= s.into_bigint());
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

    pub fn credential_presentation_gadget<CS: ConstraintSystem>(
        cs: &mut CS,
        id: AllocatedScalar,
        Q_holder: AllocatedPoint,
        expiration: AllocatedScalar,
        Q_issuer: CortadoAffine,
        c: AllocatedScalar,
        R: AllocatedPoint,
        s: AllocatedScalar,
    ) -> Result<(), R1CSError> {
        let input = [
            LinearCombination::from(id.variable), 
            LinearCombination::from(Q_holder.x.variable), 
            LinearCombination::from(Q_holder.y.variable), 
            LinearCombination::from(expiration.variable), 
            LinearCombination::from(Variable::One() * Q_issuer.x().unwrap().into_scalar()), 
            LinearCombination::from(Variable::One() * Q_issuer.y().unwrap().into_scalar()),
            LinearCombination::from(R.x.variable), 
            LinearCombination::from(R.y.variable),
        ];

        let hash_lc = Poseidon_hash_8_constraints(cs, input, &get_poseidon_params(), &SboxType::Penta)?;
        cs.constrain(c.variable - hash_lc);
        
        let P = scalar_mul_gadget_v1(cs, s, CortadoAffine::generator())?;
        let Q = scalar_mul_gadget_v1(cs, c, Q_issuer)?;

        // check that R = P - Q
        co_linear_gadget(cs, P, Q, R)
        //Ok(())
    }

    /// create credential presentation proof
    pub fn present(&self) -> Result<CredentialPresentationProof, R1CSError> {
        let start = Instant::now();
        let mut transcript = Transcript::new(b"GadgetCredentialPresentation");
        let pc_gens = PedersenGens::default();
        let mut prover = r1cs::Prover::new(&pc_gens, &mut transcript);
        let (id_var, id_comm) = prover.allocate_scalar(self.claims.id.into_scalar())?;
        let (Q_holder, Q_holder_comm) = prover.allocate_point(
            self.claims.Q.x().unwrap().into_scalar(),
            self.claims.Q.y().unwrap().into_scalar(),
        )?;
        let (exp_var, exp_comm) = prover.allocate_scalar(cortado::Fq::from(self.claims.expiration).into_scalar())?;
        let (c_var, c_comm) = prover.allocate_scalar(self.get_hash())?;
        let (R, R_comm) = prover.allocate_point(
            self.signature.0.x().unwrap().into_scalar(),
            self.signature.0.y().unwrap().into_scalar(),
        )?;
        let (s_var, s_comm) = prover.allocate_scalar( Scalar::from_bytes_mod_order((&self.signature.1.into_bigint().to_bytes_le()[..]).try_into().unwrap() ) )?;
        Self::credential_presentation_gadget(
            &mut prover,
            id_var,
            Q_holder,
            exp_var,
            self.issuer,
            c_var,
            R,
            s_var,
        )?;
        debug!("Credential presentation gadget metrics: {:?}", prover.metrics());
        let proof = prover.prove(&BulletproofGens::new(4096, 1))?;
        debug!("Credential presentation proof generated in {:?}", start.elapsed());

        Ok(CredentialPresentationProof {
            proof,
            id_comm,
            Q_holder_comm,
            exp_comm,
            c_comm,
            R_comm,
            s_comm,
            Q_issuer: self.issuer,
        })
    }

    pub fn verify_presentation(
        proof: &CredentialPresentationProof,
    ) -> Result<(), R1CSError> {
        let start = Instant::now();
        let mut transcript = Transcript::new(b"GadgetCredentialPresentation");
        let pc_gens = PedersenGens::default();
        let mut verifier = r1cs::Verifier::new(&mut transcript);
        
        let id_var = verifier.allocate_scalar(proof.id_comm)?;
        let Q_holder = verifier.allocate_point(proof.Q_holder_comm.0, proof.Q_holder_comm.1)?;
        let exp_var = verifier.allocate_scalar(proof.exp_comm)?;
        let c_var = verifier.allocate_scalar(proof.c_comm)?;
        let R = verifier.allocate_point(proof.R_comm.0, proof.R_comm.1)?;
        let s_var = verifier.allocate_scalar(proof.s_comm)?;

        Self::credential_presentation_gadget(
            &mut verifier,
            id_var,
            Q_holder,
            exp_var,
            proof.Q_issuer,
            c_var,
            R,
            s_var,
        )?;

        verifier.verify(&proof.proof, &pc_gens, &BulletproofGens::new(4096, 1))?;
        debug!("Credential presentation proof verified in {:?}", start.elapsed());
        Ok(())
    }
}

#[test]
fn test_credential_issue_and_verify() {
    let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .try_init();

    let holder_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
    let issuer_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
    let expiration = SystemTime::now() + time::Duration::from_secs(3600); // 1 hour from now
    let holder_public_key = (CortadoAffine::generator() * holder_secret_key).into_affine();

    // Issue a credential
    let credential = Credential::issue(issuer_secret_key, expiration, holder_public_key).unwrap();
    
    // Verify the credential
    assert!(credential.verify().is_ok());

    // Create a credential presentation proof
    let proof = credential.present().unwrap();

    // Verify the credential presentation proof
    assert!(Credential::verify_presentation(&proof).is_ok());
}