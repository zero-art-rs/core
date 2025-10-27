#![allow(non_snake_case)]

use std::time::{self, Instant, SystemTime};

use crate::art::{CompressedRistretto, R1CSProof};
use crate::dh::{bin_equality_gadget, scalar_mul_gadget};
use crate::gadgets::poseidon_gadget::*;
use crate::gadgets::r1cs_utils::*;
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::SWCurveConfig};
use ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::{
    ProofError,
    r1cs::{self, ConstraintSystem, LinearCombination, Prover, R1CSError, Variable, Verifier},
};
use chrono::{DateTime, Utc};
use cortado::{self, CortadoAffine, FromScalar, Parameters, ToScalar};
use curve25519_dalek::ristretto::{self};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{Rng, thread_rng};
use tracing::{debug, info, instrument};
use zkp::toolbox::{FromBytes, SchnorrCS, ToBytes};

const TIME_DELTA_SIZE: u64 = 32; // size of the maximum time delta in bits
const TIME_PROVER_VERIFIER_TIME_TOLERANCE: u64 = 20;

fn get_poseidon_params() -> PoseidonParams {
    let width = 10;
    let (full_b, full_e) = (4, 4);
    let partial_rounds = 140;
    PoseidonParams::new(width, full_b, full_e, partial_rounds)
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialClaims {
    id: cortado::Fq,  // credential unique identifier (seed)
    Q: CortadoAffine, // credential holder public key
    expiration: u64,  // credential expiration time as UNIX timestamp
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
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct CredentialPresentationProof {
    pub proof: R1CSProof,
    pub id_comm: CompressedRistretto,
    pub Q_holder_comm: (CompressedRistretto, CompressedRistretto),
    pub claimed_time: u64,
    pub exp_comm: CompressedRistretto,
    pub k_comm: CompressedRistretto,
    pub c_comm: CompressedRistretto,
    pub R_comm: (CompressedRistretto, CompressedRistretto),
    pub s_comm: CompressedRistretto,
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
            &SboxType::Penta,
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
                R.y().unwrap().into_scalar(),
            ],
            &get_poseidon_params(),
            &SboxType::Penta,
        );
        let s = secret_key * cortado::Fr::from_le_bytes_mod_order(hash.as_bytes()) + r;

        Ok((Q, R, s))
    }

    /// issue new credential
    pub fn issue(
        issuer: cortado::Fr,
        validity_period: u64,
        holder: CortadoAffine,
    ) -> Result<Self, R1CSError> {
        let claims = CredentialClaims {
            id: cortado::Fq::rand(&mut rand::thread_rng()), // This should be a unique identifier, e.g., a hash of the holder's public key
            Q: holder,
            expiration: (Utc::now().timestamp() as u64) + validity_period, // expiration time in seconds
        };
        let (Q, R, s) = Self::sign_claims(&claims, issuer)?;

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
            &SboxType::Penta,
        );

        let R2 = (CortadoAffine::generator() * self.signature.1
            - self.issuer * cortado::Fr::from_le_bytes_mod_order(hash.as_bytes()))
        .into_affine();
        if self.signature.0 == R2 {
            Ok(())
        } else {
            Err(R1CSError::VerificationError)
        }
    }

    pub fn credential_presentation_gadget<CS: ConstraintSystem>(
        cs: &mut CS,
        // public inputs
        prover_time: u64,
        Q_issuer: CortadoAffine,
        revocation_list: Vec<Scalar>,

        // secret inputs
        id: AllocatedScalar,
        Q_holder: AllocatedPoint,
        expiration: AllocatedScalar,
        k: AllocatedScalar,
        c: AllocatedScalar,
        R: AllocatedPoint,
        s: AllocatedScalar,
    ) -> Result<(), R1CSError> {
        // add inputs for the hash
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

        // check hash
        let hash_lc =
            Poseidon_hash_8_constraints(cs, input, &get_poseidon_params(), &SboxType::Penta)?;
        cs.constrain(c.variable - hash_lc);

        // check that id is not in the revocation list
        set_non_membership_gadget(cs, id, revocation_list)?;

        // check the possesion of k
        let Q = scalar_mul_gadget(2, cs, k, CortadoAffine::generator())?;
        cs.constrain(Q_holder.x.variable - Q.x.variable);
        cs.constrain(Q_holder.y.variable - Q.y.variable);

        // check that credential is not expired
        let time_lc = LinearCombination::from(expiration.variable - prover_time);
        bin_equality_gadget(
            cs,
            &time_lc,
            expiration.assignment.map(|e| e - Scalar::from(prover_time)),
            TIME_DELTA_SIZE,
        )?;

        // compute verification equation
        let P = scalar_mul_gadget(2, cs, s, CortadoAffine::generator())?;
        let Q = scalar_mul_gadget(2, cs, c, Q_issuer)?;

        // check that R = P - Q
        co_linear_gadget(cs, P, Q, R)
    }

    /// create credential presentation proof
    pub fn present(
        &self,
        ad: &[u8],
        k: cortado::Fr,
        revocation_list: Vec<Scalar>,
    ) -> Result<CredentialPresentationProof, R1CSError> {
        let start = Instant::now();
        let mut transcript = Transcript::new(b"GadgetCredentialPresentation");
        transcript.append_message(b"ad", ad);
        let pc_gens = PedersenGens::default();
        let mut prover = r1cs::Prover::new(&pc_gens, &mut transcript);
        let (id_var, id_comm) = prover.allocate_scalar(self.claims.id.into_scalar())?;
        let (Q_holder, Q_holder_comm) = prover.allocate_point(
            self.claims.Q.x().unwrap().into_scalar(),
            self.claims.Q.y().unwrap().into_scalar(),
        )?;
        let (exp_var, exp_comm) =
            prover.allocate_scalar(cortado::Fq::from(self.claims.expiration).into_scalar())?;
        let (k_var, k_comm) = prover.allocate_scalar(k.into_scalar())?;
        let (c_var, c_comm) = prover.allocate_scalar(self.get_hash())?;
        let (R, R_comm) = prover.allocate_point(
            self.signature.0.x().unwrap().into_scalar(),
            self.signature.0.y().unwrap().into_scalar(),
        )?;
        let (s_var, s_comm) = prover.allocate_scalar(Scalar::from_bytes_mod_order(
            (&self.signature.1.into_bigint().to_bytes_le()[..])
                .try_into()
                .unwrap(),
        ))?;
        let claimed_time = Utc::now();

        Self::credential_presentation_gadget(
            &mut prover,
            claimed_time.timestamp() as u64,
            self.issuer,
            revocation_list,
            id_var,
            Q_holder,
            exp_var,
            k_var,
            c_var,
            R,
            s_var,
        )?;
        debug!(
            "Credential presentation gadget metrics: {:?}",
            prover.metrics()
        );
        let proof = prover.prove(&BulletproofGens::new(8192, 1))?;
        debug!(
            "Credential presentation proof generated in {:?}",
            start.elapsed()
        );

        Ok(CredentialPresentationProof {
            proof: R1CSProof(proof),
            id_comm: CompressedRistretto(id_comm),
            Q_holder_comm: (
                CompressedRistretto(Q_holder_comm.0),
                CompressedRistretto(Q_holder_comm.1),
            ),
            claimed_time: claimed_time.timestamp() as u64,
            exp_comm: CompressedRistretto(exp_comm),
            k_comm: CompressedRistretto(k_comm),
            c_comm: CompressedRistretto(c_comm),
            R_comm: (CompressedRistretto(R_comm.0), CompressedRistretto(R_comm.1)),
            s_comm: CompressedRistretto(s_comm),
        })
    }

    pub fn verify_presentation(
        ad: &[u8],
        proof: &CredentialPresentationProof,
        issuer_pk: CortadoAffine,
        revocation_list: Vec<Scalar>,
    ) -> Result<(), R1CSError> {
        let start = Instant::now();
        let mut transcript = Transcript::new(b"GadgetCredentialPresentation");
        transcript.append_message(b"ad", ad);
        let pc_gens = PedersenGens::default();
        let mut verifier = r1cs::Verifier::new(&mut transcript);

        let id_var = verifier.allocate_scalar(proof.id_comm.0)?;
        let Q_holder = verifier.allocate_point(proof.Q_holder_comm.0.0, proof.Q_holder_comm.1.0)?;
        let exp_var = verifier.allocate_scalar(proof.exp_comm.0)?;
        let k_var = verifier.allocate_scalar(proof.k_comm.0)?;
        let c_var = verifier.allocate_scalar(proof.c_comm.0)?;
        let R = verifier.allocate_point(proof.R_comm.0.0, proof.R_comm.1.0)?;
        let s_var = verifier.allocate_scalar(proof.s_comm.0)?;

        Self::credential_presentation_gadget(
            &mut verifier,
            proof.claimed_time,
            issuer_pk,
            revocation_list,
            id_var,
            Q_holder,
            exp_var,
            k_var,
            c_var,
            R,
            s_var,
        )?;

        if Utc::now()
            - chrono::DateTime::from_timestamp(proof.claimed_time as i64, 0).unwrap_or_default()
            > chrono::Duration::seconds(TIME_PROVER_VERIFIER_TIME_TOLERANCE as i64)
        {
            debug!(
                "Credential presentation proof claimed time is within tolerance {:?}",
                Utc::now()
                    - chrono::DateTime::from_timestamp(proof.claimed_time as i64, 0)
                        .unwrap_or_default()
            );
            return Err(R1CSError::VerificationError);
        }

        verifier.verify(&proof.proof.0, &pc_gens, &BulletproofGens::new(8192, 1))?;
        debug!(
            "Credential presentation proof verified in {:?}",
            start.elapsed()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_issue_and_verify() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();

        let holder_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
        let issuer_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
        let issuer_public_key = (CortadoAffine::generator() * issuer_secret_key).into_affine();
        let validity_period = 3600; // 1 hour validity
        let holder_public_key = (CortadoAffine::generator() * holder_secret_key).into_affine();
        let revocation_list = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ]; // Example revocation list

        // Issue a credential
        let credential =
            Credential::issue(issuer_secret_key, validity_period, holder_public_key).unwrap();

        // Verify the credential
        assert!(credential.verify().is_ok());

        // Create a credential presentation proof
        let proof = credential
            .present(b"cred", holder_secret_key, revocation_list.clone())
            .unwrap();

        // Verify the credential presentation proof
        assert!(
            Credential::verify_presentation(b"cred", &proof, issuer_public_key, revocation_list)
                .is_ok()
        );
    }

    #[test]
    fn test_revoked_credential() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();

        let holder_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
        let issuer_secret_key = cortado::Fr::rand(&mut rand::thread_rng());
        let issuer_public_key = (CortadoAffine::generator() * issuer_secret_key).into_affine();
        let validity_period = 3600; // 1 hour validity
        let holder_public_key = (CortadoAffine::generator() * holder_secret_key).into_affine();

        // Issue a credential
        let credential =
            Credential::issue(issuer_secret_key, validity_period, holder_public_key).unwrap();

        // Verify the credential
        assert!(credential.verify().is_ok());

        // Create a credential presentation proof
        let revocation_list = vec![credential.claims.id.into_scalar()]; // Revoking the issued credential
        let proof = credential
            .present(b"cred", holder_secret_key, revocation_list.clone())
            .unwrap();

        // Verify the credential presentation proof should fail due to revocation
        assert!(
            Credential::verify_presentation(b"cred", &proof, issuer_public_key, revocation_list)
                .is_err()
        );
    }
}
