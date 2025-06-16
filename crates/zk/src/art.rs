
#![allow(non_snake_case)]
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand_core::{le, OsRng};
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::VariableBaseMSM;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use zkp::toolbox::cross_dleq::{CrossDLEQProof, CrossDleqProver, CrossDleqVerifier, PedersenBasis};
use zkp::toolbox::dalek_ark::{ark_to_ristretto255, ristretto255_to_ark, scalar_to_ark};
use crate::curve::cortado::{self, CortadoAffine, Parameters, ToScalar, FromScalar};
use crate::dh::dh_gadget_v2;

#[derive(Clone)]
pub struct ARTProof {
    pub Rι: Vec<R1CSProof>, // Rι gadget proofs
    pub Rσ: CrossDLEQProof<CortadoAffine>, // cross-group relation proof
    pub R: Vec<CortadoAffine>, // auxiliary public keys
}

/*
impl ARTProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>, zkp::ProofError> {
        let mut bytes = vec![];
        for proof in &self.Rι {
            bytes.extend_from_slice(&proof.to_bytes()?);
        }
        bytes.extend_from_slice(&self.Rσ.to_bytes()?);
        for r in &self.R {
            bytes.extend_from_slice(&r.to_bytes()?);
        }
        Ok(bytes)
    }
}
*/

/// Prove the cross-group relation Rσ for a given basis:
/// Rσ = { (λ_a, r; Q ∈ 𝔾_1^k, Com ∈ 𝔾_2^k) | ∀i ∈ [0, k-1], Q[i] = λ_a[i] * H_1, Com(λ_a[i]) = λ_a[i] * G_2 + r[i] * H_2 }
pub fn Rσ_prove(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    s : Vec<cortado::Fr>, // auxiliary 𝔾_1 secrets
    λ_a: Vec<Scalar>, // cross-group secrets
    blindings: Vec<Scalar>,
) -> Result<(CrossDLEQProof<CortadoAffine>, Vec<CortadoAffine>), zkp::ProofError> {
    let start = Instant::now();
    let mut prover: CrossDleqProver<CortadoAffine> = CrossDleqProver::new(basis);
    let mut R = vec![];
    for s in s {
        R.push(prover.add_dl_statement(s));
    }
    for i in 0..λ_a.len() {
        let λ = cortado::Fq::from_scalar(λ_a[i]).into_bigint();
        let r = scalar_to_ark(&blindings[i]);
        
        prover.add_dleq_statement(λ , r);
    }
    let proof = prover.prove_cross()?;
    let b = proof.to_bytes()?.len();
    debug!("Rσ_prove time: {:?}, proof len: {b}", start.elapsed());
    Ok((proof, R))
}

pub fn Rσ_verify(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    proof: CrossDLEQProof<CortadoAffine>,
) -> Result<(), zkp::ProofError> {
    let start = Instant::now();
    let mut verifier: CrossDleqVerifier<CortadoAffine> = CrossDleqVerifier::new(basis);
    for R in R {
        verifier.add_dl_statement(R);
    }
    for c in proof.commitments {
        verifier.add_dleq_statement(c);
    }
    verifier.verify_cross(&proof.proof)?;
    debug!("Rσ_verify time: {:?}", start.elapsed());
    Ok(())
}

/// Prove the Rι gadget for a given depth k:
/// Rι = { (λ_a; Q_b) | ∀i ∈ [0, k-1], λ_a[i+1] = Q_b[i] * λ_a[i] }
pub fn Rι_prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
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
    let proof_len = proofs.lock().unwrap().iter()
        .filter_map(|x| x.as_ref())
        .map(|x| x.to_bytes().len())
        .sum::<usize>();
    debug!("ARTGadget for depth {k} proving time: {:?}, proof_len: {proof_len}", start.elapsed());
    Ok((proofs.lock().unwrap().iter().map(|x| x.as_ref().unwrap().clone()).collect(), commitments.lock().unwrap().clone()))
}

pub fn Rι_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proofs: Vec<R1CSProof>,
    Q_b: Vec<CortadoAffine>, // k
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

pub fn random_witness_gen(k: u32) -> (Vec<CortadoAffine>, Vec<Scalar>) {
    let start = Instant::now();
    let mut blinding_rng = rand::thread_rng();
    let mut λ = Vec::new();
    let mut Q = Vec::new();
    let r: cortado::Fr = blinding_rng.r#gen();
    let mut λ_a = Scalar::from_bytes_mod_order((&r.into_bigint().to_bytes_le()[..]).try_into().unwrap());
    λ.push(λ_a);
    for i in 0..k {
        let r: cortado::Fr = blinding_rng.r#gen();
        let Q_b = (CortadoAffine::generator() * r).into_affine();
        Q.push(Q_b);
        let R = (Q_b * cortado::Fr::from_le_bytes_mod_order(&λ_a.to_bytes())).into_affine();
        λ_a = R.x().unwrap().into_scalar();
        λ.push(λ_a);
    }
    debug!("Witness generation for Rι with depth {} took {:?}", k, start.elapsed());
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

pub fn art_prove(
    bp_gens: &BulletproofGens,
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
    λ_a: Vec<Scalar>, // secrets
    s: Vec<cortado::Fr>, // auxiliary 𝔾_1 secrets
    blindings: Vec<Scalar>, // blinding factors for λ_a
) -> Result<ARTProof, R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens{B: ark_to_ristretto255(basis.G_2).unwrap(), B_blinding: ark_to_ristretto255(basis.H_2).unwrap()};
    let (Rι_proofs, _) = Rι_prove(&pc_gens, bp_gens, Q_b.clone(), λ_a.clone(), blindings.clone())?;
    let (Rσ_proof, R) = Rσ_prove(
        basis,
        s,
        λ_a,
        blindings
    ).map_err(|e| R1CSError::GadgetError{ description: format!("Rσ_prove failed: {e:?}") })?;
    
    debug!("ART proof generation time: {:?}", start.elapsed());
    Ok(ARTProof {
        Rι: Rι_proofs,
        Rσ: Rσ_proof,
        R,
    })
}

pub fn art_verify(
    bp_gens: &BulletproofGens,
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
    proof: ARTProof
) -> Result<(), R1CSError> {
    let start = Instant::now();
    let B: Vec<BigInt<4>> = (0..4).map(|x|  BigInt::<4>::from(1u64) << (x*64)).collect();
    let pc_gens = PedersenGens{B: ark_to_ristretto255(basis.G_2).unwrap(), B_blinding: ark_to_ristretto255(basis.H_2).unwrap()};
    let commitments = proof.Rσ.commitments.iter().map(|c| 
            ark_to_ristretto255(<Ed25519Affine as AffineRepr>::Group::msm(
                    &[c.Com_x0, c.Com_x1, c.Com_x2, c.Com_x3],
                    B.iter().map(|&x| ark_ed25519::Fr::from(x)).collect::<Vec<_>>().as_slice(),
                ).unwrap().into_affine()
            ).unwrap().compress()
        ).collect::<Vec<_>>();
    Rι_verify(&pc_gens, bp_gens, proof.Rι, Q_b, commitments)?;
    Rσ_verify(basis, proof.R, proof.Rσ)
        .map_err(|e| R1CSError::GadgetError{ description: format!("Rσ_verify failed: {e:?}") })?;
    
    info!("ART proof verification time: {:?}", start.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_Rι_roundtrip() {
        assert!(Rι_roundtrip(7).is_ok());
    }

    #[test]
    fn test_Rσ_roundtrip() {
        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        
        let k = 7;
        let (Q, λ) = random_witness_gen(k);
        let s = (0..2).map(|_| cortado::Fr::rand(&mut thread_rng())).collect::<Vec<_>>();
        let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut thread_rng())).collect();
        let (proof, R) = Rσ_prove(
            basis.clone(),
            s,
            λ.clone(),
            blindings
        ).expect("Rσ_prove failed");
        assert!(Rσ_verify(basis, R, proof).is_ok(), "Rσ_verify failed");
    }

    #[test]
    fn test_art_roundtrip() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .init();

        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        
        let k = 7;
        let (Q, λ) = random_witness_gen(k);
        let s = (0..2).map(|_| cortado::Fr::rand(&mut thread_rng())).collect::<Vec<_>>();
        let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut thread_rng())).collect();
        
        let proof = art_prove(
            &BulletproofGens::new(2048, 1),
            basis.clone(),
            Q.clone(),
            λ.clone(),
            s,
            blindings
        ).expect("art_prove failed");
        
        assert!(art_verify(
            &BulletproofGens::new(2048, 1),
            basis,
            Q,
            proof
        ).is_ok(), "art_verify failed");
    }
}
