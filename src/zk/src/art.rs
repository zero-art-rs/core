
#![allow(non_snake_case)]
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use rand_core::{le, OsRng};
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use zkp::toolbox::cross_dleq::CrossDLEQProof;
use crate::curve::g2::{self as G2, Parameters, ToScalar};
use crate::dh::dh_gadget_v2;

pub fn Rσ_prove(
    λ_a: Vec<Scalar>,
    blindings: Vec<Scalar>,
) -> Result<CrossDLEQProof<G2::G2Affine>, zkp::ProofError> {
    todo!()
}

/// Prove the Rι gadget for a given depth k:
/// Rι = { (λ_a; Q_b) | ∀i ∈ [0, k-1], λ_a[i+1] = Q_b[i] * λ_a[i] }
pub fn Rι_prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    Q_b: Vec<G2::G2Affine>, // reciprocal public keys
    λ_a: Vec<Scalar>, // secrets
    blindings: Vec<Scalar>, // blinding factors for λ_a
) -> Result<(Vec<R1CSProof>, Vec<CompressedRistretto>), R1CSError> {
    let start = Instant::now();
    let k = Q_b.len();
    assert!(k == λ_a.len() - 1, "length mismatch");
    let commitments = Arc::new(Mutex::new(vec![CompressedRistretto::default(); k+1]));
    let proofs = Arc::new(Mutex::new(vec![None; k]));
        
    #[cfg(feature = "multi_thread_prover")]
    {
        let mut handles = Vec::new();
        for i in 0..k {
            let proofs = proofs.clone();
            let commitments = commitments.clone();
            let pc_gens = pc_gens.clone();
            let bp_gens = bp_gens.clone();
            let Q_b_i = Q_b[i].clone();
            let λ_a_i = λ_a[i];
            let λ_a_next = λ_a[i+1];
            let blindings_i = (blindings[i], blindings[i+1]);
            
            handles.push(std::thread::spawn(move || {
                let mut transcript = Transcript::new(b"ARTGadget");
                let mut prover = Prover::new(&pc_gens, &mut transcript);
                let (a_commitment, var_a) = prover.commit(λ_a_i, blindings_i.0);
                let (ab_commitment, var_ab) = prover.commit(λ_a_next, blindings_i.1);
                {
                    let mut commitments = commitments.lock().unwrap();
                    commitments[i] = a_commitment;
                    if i == k - 1 {
                        commitments[i+1] = ab_commitment;
                    }
                }
    
                dh_gadget_v2(&mut prover, Some(λ_a_i), Q_b_i, var_a, var_ab).unwrap();
    
                let proof = prover.prove(&bp_gens).unwrap();
                {
                    let mut proofs = proofs.lock().unwrap();
                    proofs[i] = Some(proof);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }
    #[cfg(not(feature = "multi_thread_prover"))]
    {
        for i in 0..k {
            let mut transcript = Transcript::new(b"ARTGadget");
            let mut prover = Prover::new(&pc_gens, &mut transcript);
            let (a_commitment, var_a) = prover.commit(λ_a[i], blindings[i]);
            let (ab_commitment, var_ab) = prover.commit(λ_a[i+1], blindings[i+1]);
            {
                let mut commitments = commitments.lock().unwrap();
                commitments[i] = a_commitment;
                if i == k - 1 {
                    commitments[i+1] = ab_commitment;
                }
            }

            dh_gadget_v2(&mut prover, Some(λ_a[i]), Q_b[i], var_a, var_ab).unwrap();

            let proof = prover.prove(&bp_gens).unwrap();
            {
                let mut proofs = proofs.lock().unwrap();
                proofs[i] = Some(proof);
            }
        }
    }

    debug!("ARTGadget for depth {k} proving time: {:?}", start.elapsed());
    Ok((proofs.lock().unwrap().iter().map(|x| x.as_ref().unwrap().clone()).collect(), commitments.lock().unwrap().clone()))
}

pub fn Rι_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proofs: Vec<R1CSProof>,
    Q_b: Vec<G2::G2Affine>, // k
    commitments: Vec<CompressedRistretto>, // k+1
) -> Result<(), R1CSError> {
    let start = Instant::now();
    assert!(Q_b.len() == commitments.len() - 1, "length mismatch");
    let k = Q_b.len();
    
    #[cfg(feature = "multi_thread_verifier")] 
    {
        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();
        for i in 0..k {
            let tx = tx.clone();
            let pc_gens = pc_gens.clone();
            let bp_gens = bp_gens.clone();
            let Q_b_i = Q_b[i].clone();
            let proof_i = proofs[i].clone();
            let commitment_i = commitments[i];
            let commitment_next = commitments[i+1];

            handles.push(std::thread::spawn(move || {
                let mut transcript = Transcript::new(b"ARTGadget");
                let mut verifier = Verifier::new(&mut transcript);
                let var_a = verifier.commit(commitment_i);
                let var_ab = verifier.commit(commitment_next);
                let _ = tx.send(dh_gadget_v2(&mut verifier, None, Q_b_i, var_a, var_ab)
                    .and_then(|_| verifier.verify(&proof_i, &pc_gens, &bp_gens)));
            }));
        }
        for _ in handles {
            rx.recv().unwrap()?;
        }
    }
    #[cfg(not(feature = "multi_thread_verifier"))]
    {
        for i in 0..k {
            let mut transcript = Transcript::new(b"ARTGadget");
            let mut verifier = Verifier::new(&mut transcript);
            let var_a = verifier.commit(commitments[i]);
            let var_ab = verifier.commit(commitments[i+1]);
            dh_gadget_v2(&mut verifier, None, Q_b[i], var_a, var_ab)?;
            verifier.verify(&proofs[i], &pc_gens, &bp_gens)?;
        }
    }
    debug!("ARTGadget for depth {} verification time: {:?}", Q_b.len(), start.elapsed());

    Ok(())
}

pub fn random_witness_gen(k: u32) -> (Vec<G2::G2Affine>, Vec<Scalar>) {
    let mut blinding_rng = rand::thread_rng();
    let mut λ = Vec::new();
    let mut Q = Vec::new();
    let r: G2::Fr = blinding_rng.r#gen();
    let mut λ_a = Scalar::from_bytes_mod_order((&r.into_bigint().to_bytes_le()[..]).try_into().unwrap());
    λ.push(λ_a);
    for i in 0..k {
        let r: G2::Fr = blinding_rng.r#gen();
        let Q_b = (G2::G2Affine::generator() * r).into_affine();
        Q.push(Q_b);
        let R = (Q_b * G2::Fr::from_le_bytes_mod_order(&λ_a.to_bytes())).into_affine();
        λ_a = R.x().unwrap().into_scalar();
        λ.push(λ_a);
    }
    
    (Q, λ)
}

pub fn Rι_roundtrip(k: u32) -> Result<(), R1CSError> {
    let mut blinding_rng = rand::thread_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2048, 1);
    let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut blinding_rng)).collect();
    let (Q, λ) = random_witness_gen(k);
    let (proofs, commitments) = Rι_prove(
        &pc_gens, 
        &bp_gens, 
        Q.clone(), 
        λ,
        blindings
    )?;

    Rι_verify(&pc_gens, &bp_gens, proofs, Q, commitments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_Rι_roundtrip() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .init();
        assert!(Rι_roundtrip(10).is_ok());
    }
}
