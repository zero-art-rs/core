
#![allow(non_snake_case)]
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use ark_std::log2;
use rand_core::{le, OsRng};
use bulletproofs::r1cs::{R1CSError, R1CSProof as BPR1CSProof, Prover, Verifier, ConstraintSystem};
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
use zkp::toolbox::{prover::Prover as SigmaProver, verifier::Verifier as SigmaVerifier, FromBytes, ToBytes};
use zkp::toolbox::dalek_ark::{ark_to_ristretto255, ristretto255_to_ark, scalar_to_ark};
use zkp::toolbox::SchnorrCS;
use cortado::{self, CortadoAffine, Parameters, ToScalar, FromScalar};

use zkp::CompactProof;
use crate::dh::{dh_gadget, art_level_gadget};
use crate::gadgets::r1cs_utils::AllocatedScalar;

#[derive(Clone)]
pub struct R1CSProof(BPR1CSProof);

#[derive(Clone)]
pub struct CompressedRistrettoWrapper(CompressedRistretto);

#[cfg(feature = "cross_sigma")]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ARTProof {
    pub Rι: Vec<R1CSProof>, // Rι gadget proofs
    pub Rσ: CrossDLEQProof<CortadoAffine>, // cross-group relation proof
}

#[cfg(not(feature = "cross_sigma"))]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ARTProof {
    pub Rι: (Vec<R1CSProof>, Vec<CompressedRistrettoWrapper>), // Rδ gadget proofs
    pub Rσ: CompactProof<cortado::Fr>, // sigma part of the proof
}

impl CanonicalSerialize for R1CSProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // Serialize the proof
        let proof_bytes = self.0.to_bytes();
        (proof_bytes.len() as u32).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&proof_bytes)?;

        Ok(())
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        let proof_size = self.0.to_bytes().len();
        proof_size + 4
    }
}

impl ark_serialize::Valid for R1CSProof {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for R1CSProof {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        // Deserialize the proof
        let proof_len = u32::deserialize_compressed(&mut reader)? as usize;
        let mut proof_bytes = vec![0u8; proof_len];
        reader.read_exact(&mut proof_bytes)?;
        let proof = bulletproofs::r1cs::R1CSProof::from_bytes(&proof_bytes)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

        Ok(R1CSProof ( proof ))
    }
}

impl CanonicalSerialize for CompressedRistrettoWrapper {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // Serialize the proof
        let proof_bytes = self.0.to_bytes();
        (proof_bytes.len() as u32).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&proof_bytes)?;

        Ok(())
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        let proof_size = self.0.to_bytes().len();
        proof_size + 4
    }
}

impl ark_serialize::Valid for CompressedRistrettoWrapper {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for CompressedRistrettoWrapper {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        // Deserialize the proof
        let proof_len = u32::deserialize_compressed(&mut reader)? as usize;
        let mut proof_bytes = vec![0u8; proof_len];
        reader.read_exact(&mut proof_bytes)?;
        let point = CompressedRistretto::from_slice(&proof_bytes)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

        Ok(CompressedRistrettoWrapper ( point ))
    }
}

/// Estimate the number of generators needed for the given depth
pub fn estimate_bp_gens(mut height: usize, dh_ver: u32) -> usize {
    #[cfg(feature = "multi_thread_prover")]
    {
        height = 1
    }
    let eps = 5;

    let level_complexity: usize = match dh_ver {
        #[cfg(feature = "cross_sigma")]
        1 => 1521,
        #[cfg(not(feature = "cross_sigma"))]
        1 => 3042,
        #[cfg(feature = "cross_sigma")]
        2 => 1268,
        #[cfg(not(feature = "cross_sigma"))]
        2 => 2536,
        _ => 0,
    };
    let log_depth = log2(height * (level_complexity + eps));
    1 << log_depth
}

/// Prove the cross-group relation Rσ for a given basis:
/// Rσ = { (λ_a, r; Q ∈ 𝔾_1^k, Com ∈ 𝔾_2^k) | ∀i ∈ [0, k-1], Q[i] = λ_a[i] * H_1, Com(λ_a[i]) = λ_a[i] * G_2 + r[i] * H_2 }
pub fn Rσ_prove(
    transcript: &mut Transcript,
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    s : Vec<cortado::Fr>, // auxiliary 𝔾_1 secrets
    λ_a: Vec<cortado::Fr>, // cross-group secrets
    blindings: Vec<Scalar>,
) -> Result<(CrossDLEQProof<CortadoAffine>, Vec<CortadoAffine>), zkp::ProofError> {
    let start = Instant::now();
    let mut prover: CrossDleqProver<CortadoAffine> = CrossDleqProver::new(basis, transcript);
    
    let mut R = vec![];
    for s in s {
        R.push(prover.add_dl_statement(s));
    }
    for i in 0..λ_a.len() {
        let λ = λ_a[i];
        let r = scalar_to_ark(&blindings[i]);
        
        prover.add_dleq_statement(λ.into() , r);
    }
    let proof = prover.prove_cross()?;
    let b = proof.to_bytes()?.len();
    debug!("Rσ_prove time: {:?}, proof len: {b}", start.elapsed());
    Ok((proof, R))
}

pub fn Rσ_verify(
    transcript: &mut Transcript,
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    Q_a: Vec<CortadoAffine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    proof: CrossDLEQProof<CortadoAffine>,
) -> Result<(), zkp::ProofError> {
    let start = Instant::now();
    let mut verifier: CrossDleqVerifier<CortadoAffine> = CrossDleqVerifier::new(basis, transcript);
    for R in R {
        verifier.add_dl_statement(R);
    }
    for (i, c) in proof.commitments.iter().enumerate() {
        let mut c = c.clone();
        c.Q = Q_a[i].clone();
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
        
    #[cfg(feature = "multi_thread_prover")]
    {
        let commitments = Arc::new(Mutex::new(vec![CompressedRistretto::default(); k+1]));
        let proofs = Arc::new(Mutex::new(vec![None; k]));
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
                let λ_a_i = AllocatedScalar::new(var_a, Some(λ_a_i)); 
                let λ_a_next = AllocatedScalar::new(var_ab, Some(λ_a_next)); 
                {
                    let mut commitments = commitments.lock().unwrap();
                    commitments[i] = a_commitment;
                    if i == k - 1 {
                        commitments[i+1] = ab_commitment;
                    }
                }
    
                dh_gadget(2, &mut prover, λ_a_i, λ_a_next, Q_b_i).unwrap();
    
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

        let proof_len = proofs.lock().unwrap().iter()
            .filter_map(|x| x.as_ref())
            .map(|x| x.to_bytes().len())
            .sum::<usize>();
        debug!("Rι_prove (parallel) for depth {k} proving time: {:?}, proof_len: {proof_len}", start.elapsed());
        Ok((proofs.lock().unwrap().iter().map(|x| R1CSProof(x.as_ref().unwrap().clone()) ).collect(), commitments.lock().unwrap().clone()))
    }
    #[cfg(not(feature = "multi_thread_prover"))]
    {
        let mut commitments = Vec::new();
        let mut vars = Vec::new();
        let mut transcript = Transcript::new(b"ARTGadget");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        for i in 0..k+1 {
            let (a_commitment, var_a) = prover.commit(λ_a[i], blindings[i]);
            commitments.push(a_commitment);
            vars.push(AllocatedScalar::new(var_a, Some(λ_a[i])));
        }
        for i in 0..k {
            dh_gadget(2, &mut prover, vars[i], vars[i+1], Q_b[i])?;
        }
        let proof = prover.prove(&bp_gens)?;

        debug!("Rι_prove (integral) for depth {} proving time: {:?}, proof_len: {}", k, start.elapsed(), proof.to_bytes().len());
        Ok((vec![R1CSProof(proof)], commitments))
    }
   
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
                let λ_a_i = AllocatedScalar::new(var_a, None); 
                let λ_a_next = AllocatedScalar::new(var_ab, None); 
                let _ = tx.send(
                    dh_gadget(2, &mut verifier, λ_a_i, λ_a_next, Q_b_i)
                        .and_then(|_| verifier.verify(&proof_i.0, &pc_gens, &bp_gens))
                );
            }));
        }
        for _ in handles {
            rx.recv().unwrap()?;
        }
    }
    #[cfg(not(feature = "multi_thread_verifier"))]
    {
        let mut transcript = Transcript::new(b"ARTGadget");
        let mut verifier = Verifier::new(&mut transcript);
        let mut vars = Vec::new();
        for i in 0..k+1 {
            let var_a = verifier.commit(commitments[i]);
            vars.push(AllocatedScalar::new(var_a, None));
        }

        for i in 0..k {
            dh_gadget(2, &mut verifier, vars[i], vars[i+1], Q_b[i])?;
        }
        verifier.verify(&proofs[0].0, &pc_gens, &bp_gens)?;
    }
    debug!("Rι_verify for depth {} verification time: {:?}", Q_b.len(), start.elapsed());

    Ok(())
}

pub fn Rδ_prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
    Q_ab: Vec<CortadoAffine>, // path public keys
    λ_a: Vec<Scalar>, // secrets
    blindings: Vec<Scalar>, // blinding factors for λ_a
    
) -> Result<(Vec<R1CSProof>, Vec<CompressedRistrettoWrapper>), R1CSError> {
    let start = Instant::now();
    let k = Q_b.len();
    assert!(k == λ_a.len() - 1, "length mismatch");
        
    #[cfg(feature = "multi_thread_prover")]
    {
        let commitments = Arc::new(Mutex::new(vec![CompressedRistretto::default(); k+1]));
        let proofs = Arc::new(Mutex::new(vec![None; k]));
        let mut handles = Vec::new();
        for i in 0..k {
            let proofs = proofs.clone();
            let commitments = commitments.clone();
            let pc_gens = pc_gens.clone();
            let bp_gens = bp_gens.clone();
            let Q_b_i = Q_b[i].clone();
            let Q_ab_i = Q_ab[i].clone();
            let λ_a_i = λ_a[i];
            let λ_a_next = λ_a[i+1];
            let blindings_i = (blindings[i], blindings[i+1]);
            
            handles.push(std::thread::spawn(move || {
                let mut transcript = Transcript::new(b"ARTGadget");
                let mut prover = Prover::new(&pc_gens, &mut transcript);
                let (a_commitment, var_a) = prover.commit(λ_a_i, blindings_i.0);
                let (ab_commitment, var_ab) = prover.commit(λ_a_next, blindings_i.1);
                let λ_a_i = AllocatedScalar::new(var_a, Some(λ_a_i)); 
                let λ_a_next = AllocatedScalar::new(var_ab, Some(λ_a_next)); 
                {
                    let mut commitments = commitments.lock().unwrap();
                    commitments[i] = a_commitment;
                    if i == k - 1 {
                        commitments[i+1] = ab_commitment;
                    }
                }
    
                art_level_gadget(2, &mut prover, λ_a_i, λ_a_next, Q_ab_i, Q_b_i).unwrap();

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

        let proof_len = proofs.lock().unwrap().iter()
            .filter_map(|x| x.as_ref())
            .map(|x| x.to_bytes().len())
            .sum::<usize>();
        debug!("Rδ_prove (parallel) for depth {k} proving time: {:?}, proof_len: {proof_len}", start.elapsed());
        Ok((
            proofs.lock().unwrap().iter().map(|x| R1CSProof(x.as_ref().unwrap().clone()) ).collect(),
            commitments.lock().unwrap().iter().map(|point| CompressedRistrettoWrapper(*point)).collect()
        ))
    }
    #[cfg(not(feature = "multi_thread_prover"))]
    {
        let mut commitments = Vec::new();
        let mut vars = Vec::new();
        let mut transcript = Transcript::new(b"ARTGadget");
        let mut prover = Prover::new(pc_gens, &mut transcript);

        for i in 0..k+1 {
            let (a_commitment, var_a) = prover.commit(λ_a[i], blindings[i]);
            commitments.push(a_commitment);
            vars.push(AllocatedScalar::new(var_a, Some(λ_a[i])));
        }
        for i in 0..k {
            art_level_gadget(2, &mut prover, vars[i], vars[i+1], Q_ab[i], Q_b[i])?;
        }
        let m = prover.metrics();
        let proof = prover.prove(&bp_gens)?;

        debug!("Rδ_prove for depth {} proving time: {:?}, proof_len: {}, gadget size: {:?}", k, start.elapsed(), proof.to_bytes().len(), m.multipliers);
        Ok((vec![R1CSProof(proof)], commitments))
    }
}

pub fn Rδ_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proofs: Vec<R1CSProof>,
    Q_b: Vec<CortadoAffine>, // k
    Q_ab: Vec<CortadoAffine>, // k
    commitments: Vec<CompressedRistrettoWrapper>, // k+1
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
            let Q_ab_i = Q_ab[i].clone();
            let proof_i = proofs[i].clone();
            let commitment_i = commitments[i].0;
            let commitment_next = commitments[i+1].0;

            handles.push(std::thread::spawn(move || {
                let mut transcript = Transcript::new(b"ARTGadget");
                let mut verifier = Verifier::new(&mut transcript);
                let var_a = verifier.commit(commitment_i);
                let var_ab = verifier.commit(commitment_next);
                let λ_a_i = AllocatedScalar::new(var_a, None); 
                let λ_a_next = AllocatedScalar::new(var_ab, None); 
                let _ = tx.send(
                    art_level_gadget(2, &mut verifier, λ_a_i, λ_a_next, Q_ab_i, Q_b_i)
                        .and_then(|_| verifier.verify(&proof_i.0, &pc_gens, &bp_gens))
                );
            }));
        }
        for _ in handles {
            rx.recv().unwrap()?;
        }
    }
    #[cfg(not(feature = "multi_thread_verifier"))]
    {
        let mut transcript = Transcript::new(b"ARTGadget");
        let mut verifier = Verifier::new(&mut transcript);
        let mut vars = Vec::new();
        for i in 0..k+1 {
            let var_a = verifier.commit(commitments[i].0);
            vars.push(AllocatedScalar::new(var_a, None));
        }

        for i in 0..k {
            art_level_gadget(2, &mut verifier, vars[i], vars[i+1], Q_ab[i], Q_b[i])?;
        }
        verifier.verify(&proofs[0].0, &pc_gens, &bp_gens)?;
    }
    debug!("Rδ_verify for depth {} verification time: {:?}", Q_b.len(), start.elapsed());

    Ok(())
}

pub fn random_witness_gen(k: u32) -> (Vec<cortado::Fr>, Vec<CortadoAffine>, Vec<CortadoAffine>) {
    let start = Instant::now();
    let mut blinding_rng = rand::thread_rng();
    let mut λ = Vec::new();
    let mut Q_a = Vec::new();
    let mut Q_b = Vec::new();
    let mut λ_a: cortado::Fr = blinding_rng.r#gen();
    Q_a.push((CortadoAffine::generator() * λ_a).into_affine());
    λ.push(λ_a);
    
    for i in 0..k {
        let r: cortado::Fr = blinding_rng.r#gen();
        let q_b = (CortadoAffine::generator() * r).into_affine();
        Q_b.push(q_b);
        let R = (q_b * λ_a).into_affine();
        λ_a = R.x().unwrap().into_bigint().into();
        λ.push(λ_a);
        let q_a = (CortadoAffine::generator() * λ_a).into_affine();
        Q_a.push(q_a);
    }
    debug!("Witness generation for Rι with depth {} took {:?}", k, start.elapsed());
    (λ, Q_a, Q_b)
}

/// generate an ART update proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself),
/// path public keys Q_a, reciprocal co-path public keys Q_b, ART path secrets λ_a, auxiliary 𝔾_1 secrets s, and blinding factors for λ_a
pub fn art_prove(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    R: Vec<CortadoAffine>, // auxiliary public keys
    Q_a: Vec<CortadoAffine>, // path public keys
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
    λ_a: Vec<cortado::Fr>, // secrets
    s: Vec<cortado::Fr>, // auxiliary 𝔾_1 secrets
    blindings: Vec<Scalar>, // blinding factors for λ_a
) -> Result<ARTProof, R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens{B: ark_to_ristretto255(basis.G_2).unwrap(), B_blinding: ark_to_ristretto255(basis.H_2).unwrap()};
    let bp_gens = BulletproofGens::new(estimate_bp_gens(Q_b.len(), 2), 1);
    let leaf_secret = λ_a[0];
    let λ_a_scalars = λ_a.clone();
    let λ_a: Vec<Scalar> = λ_a.iter().map(|x| x.into_scalar()).collect();

    #[cfg(feature = "cross_sigma")]
    {
        let (Rι_proofs, _) = Rι_prove(&pc_gens, &bp_gens, Q_b.clone(), λ_a.clone(), blindings.clone())?;
        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        let (Rσ_proof, _) = Rσ_prove(
            &mut transcript,
            basis,
            s,
            λ_a_scalars,
            blindings
        ).map_err(|e| R1CSError::GadgetError{ description: format!("Rσ_prove failed: {e:?}") })?;

        debug!("ART proof(with cross-Σ) generation time: {:?}", start.elapsed());
        Ok(ARTProof {
            Rι: Rι_proofs,
            Rσ: Rσ_proof,
        })
    }
    #[cfg(not(feature = "cross_sigma"))]
    {
        let levels_proof = Rδ_prove(&pc_gens, &bp_gens, Q_b.clone(), Q_a[1..].into(), λ_a.clone(), blindings.clone())?;

        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        let mut prover: SigmaProver<CortadoAffine, Transcript, &mut Transcript> = SigmaProver::new(b"R_sigma", &mut transcript);
        let var_lambda = prover.allocate_scalar(b"lambda_0", leaf_secret);
        let (var_P, _) = prover.allocate_point(b"P", basis.G_1);
        let (var_Q, _) = prover.allocate_point(b"Q", Q_a[0]);
        prover.constrain(var_Q, vec![(var_lambda, var_P)]);
        for (i, s) in s.iter().enumerate() {
            let var_s = prover.allocate_scalar(b"s", *s);
            let (var_R, _) = prover.allocate_point(b"R", R[i]);
            prover.constrain(var_R, vec![(var_s, var_P)]);
        }
        let sigma_proof = prover.prove_compact();

        debug!("ART proof generation time: {:?}", start.elapsed());
        Ok(ARTProof {
            Rι: levels_proof,
            Rσ: sigma_proof,
        })
    }
}

/// verify an ART proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself),
/// reciprocal co-path public keys Q_b, and the ART proof itself
pub fn art_verify(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    R: Vec<CortadoAffine>, // auxiliary public keys
    Q_a: Vec<CortadoAffine>, // path public keys
    Q_b: Vec<CortadoAffine>, // reciprocal public keys
    proof: ARTProof
) -> Result<(), R1CSError> {
    let start = Instant::now();
    
    let pc_gens = PedersenGens{B: ark_to_ristretto255(basis.G_2).unwrap(), B_blinding: ark_to_ristretto255(basis.H_2).unwrap()};
    let bp_gens = BulletproofGens::new(estimate_bp_gens(Q_b.len(), 2), 1);
    #[cfg(feature = "cross_sigma")]
    {
        let B: Vec<BigInt<4>> = (0..4).map(|x|  BigInt::<4>::from(1u64) << (x*64)).collect();
        let commitments = proof.Rσ.commitments.iter().map(|c| 
                ark_to_ristretto255(<Ed25519Affine as AffineRepr>::Group::msm(
                        &[c.Com_x0, c.Com_x1, c.Com_x2, c.Com_x3],
                        B.iter().map(|&x| ark_ed25519::Fr::from(x)).collect::<Vec<_>>().as_slice(),
                    ).unwrap().into_affine()
                ).unwrap().compress()
            ).collect::<Vec<_>>();
        Rι_verify(&pc_gens, &bp_gens, proof.Rι, Q_b, commitments)?;
        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        Rσ_verify(&mut transcript, basis, Q_a, R, proof.Rσ)
            .map_err(|e| R1CSError::GadgetError{ description: format!("Rσ_verify failed: {e:?}") })?;
        
        debug!("ART proof(with cross-Σ) verification time: {:?}", start.elapsed());
    }
    #[cfg(not(feature = "cross_sigma"))]
    {
        Rδ_verify(&pc_gens, &bp_gens, proof.Rι.0, Q_b, Q_a[1..].into(), proof.Rι.1)?;
        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        let mut verifier: SigmaVerifier<CortadoAffine, Transcript, &mut Transcript> = SigmaVerifier::new(b"R_sigma", &mut transcript);
        let var_lambda = verifier.allocate_scalar(b"lambda_0");
        let var_P = verifier.allocate_point(b"P", basis.G_1).map_err(|_| R1CSError::GadgetError{ description: "Failed to allocate point P".to_string() })?;
        let var_Q = verifier.allocate_point(b"Q", Q_a[0].clone()).map_err(|_| R1CSError::GadgetError{ description: "Failed to allocate point Q".to_string() })?;
        verifier.constrain(var_Q, vec![(var_lambda, var_P)]);

        for (i, R) in R.iter().enumerate() {
            let var_s = verifier.allocate_scalar(b"s");
            let var_R = verifier.allocate_point(b"R", R.clone()).map_err(|_| R1CSError::GadgetError{ description: "Failed to allocate point R".to_string() })?;
            verifier.constrain(var_R, vec![(var_s, var_P)]);
        }
        verifier.verify_compact(&proof.Rσ)
            .map_err(|e| R1CSError::GadgetError{ description: format!("Rσ_verify failed: {e:?}") })?;

        debug!("ART proof verification time: {:?}", start.elapsed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zkp::ProofError;

    use super::*;

    /*fn Rι_roundtrip(k: u32) -> Result<(), R1CSError> {
        let mut blinding_rng = rand::thread_rng();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(1<<16, 1);
        let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut blinding_rng)).collect();
        let (λ, Q_a, Q_b) = random_witness_gen(k);
        let (proofs, commitments) = Rι_prove(
            &pc_gens, 
            &bp_gens, 
            Q_b.clone(), 
            λ,
            blindings
        )?;

        Rι_verify(&pc_gens, &bp_gens, proofs, Q_b, commitments)
    }

    #[test]
    fn test_Rι_roundtrip() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();
        assert!(Rι_roundtrip(1).is_ok());
        assert!(Rι_roundtrip(4).is_ok());
        assert!(Rι_roundtrip(7).is_ok());
        assert!(Rι_roundtrip(10).is_ok());
        assert!(Rι_roundtrip(15).is_ok());
    }*/

    fn Rσ_roundtrip(k: u32) -> Result<(), ProofError> {
        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        
        let (λ, Q_a, Q_b) = random_witness_gen(k);
        let s = (0..2).map(|_| cortado::Fr::rand(&mut thread_rng())).collect::<Vec<_>>();
        let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut thread_rng())).collect();
        let mut prover_transcript = Transcript::new(b"Test");
        let (proof, R) = Rσ_prove(
            &mut prover_transcript,
            basis.clone(),
            s,
            λ.clone(),
            blindings
        )?;
        let mut verifier_transcript = Transcript::new(b"Test");
        Rσ_verify(&mut verifier_transcript, basis, Q_a, R, proof)
    }

    #[test]
    fn test_Rσ_roundtrip() {
        assert!(Rσ_roundtrip(1).is_ok());
        assert!(Rσ_roundtrip(4).is_ok());
        assert!(Rσ_roundtrip(7).is_ok());
        assert!(Rσ_roundtrip(10).is_ok());
        assert!(Rσ_roundtrip(15).is_ok());
    }

    fn art_roundtrip(k: u32) -> Result<(), R1CSError> {
        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        
        let (λ, Q_a, Q_b) = random_witness_gen(k);
        let s = (0..2).map(|_| cortado::Fr::rand(&mut thread_rng())).collect::<Vec<_>>();
        let R = s.iter().map(|&x| (G_1 * x).into_affine()).collect::<Vec<_>>();

        let blindings: Vec<_> = (0..k+1).map(|_| Scalar::random(&mut thread_rng())).collect();
        
        let proof = art_prove(
            basis.clone(),
            &[0x72, 0x75, 0x73, 0x73, 0x69, 0x61, 0x64, 0x69, 0x65],
            R.clone(),
            Q_a.clone(),
            Q_b.clone(),
            λ.clone(),
            s,
            blindings
        )?;
        
        art_verify(
            basis,
            &[0x72, 0x75, 0x73, 0x73, 0x69, 0x61, 0x64, 0x69, 0x65],
            R,
            Q_a,
            Q_b,
            proof
        )
    }

    #[test]
    fn test_art_roundtrip() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();

        assert!(art_roundtrip(1).is_ok());
        assert!(art_roundtrip(4).is_ok());
        assert!(art_roundtrip(7).is_ok());
        assert!(art_roundtrip(10).is_ok());
        assert!(art_roundtrip(15).is_ok());
    }
}
