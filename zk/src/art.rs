#![allow(non_snake_case)]
use crate::aggregated_art::AggregatedTreeProof;
use crate::dh::art_level_gadget;
use crate::eligibility::*;
use crate::engine::{
    ZeroArtEngineOptions, ZeroArtProverContext, ZeroArtProverEngine, ZeroArtVerifierContext,
    ZeroArtVerifierEngine,
};
use crate::errors::ZKError;
use crate::gadgets::r1cs_utils::AllocatedScalar;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use ark_std::log2;
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, R1CSProof as BPR1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use cortado::{self, CortadoAffine, ToScalar};
use curve25519_dalek::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto as DalekCompressedRistretto;
use merlin::Transcript;
use rand::{Rng, thread_rng};
use rand_core::{CryptoRngCore, OsRng, le};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tracing::debug;
use tracing_subscriber::field::debug;
use zkp::toolbox::cross_dleq::PedersenBasis;

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverNodeData<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
    pub secret_key: G::ScalarField,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub(crate) struct ProverNodeDataWithBlinding<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
    pub secret_key: G::ScalarField,
    pub blinding_factor: Scalar,
}

impl<G> ProverNodeData<G>
where
    G: AffineRepr,
{
    pub(crate) fn with_blinding(&self, blinding: Scalar) -> ProverNodeDataWithBlinding<G> {
        ProverNodeDataWithBlinding {
            public_key: self.public_key,
            co_public_key: self.co_public_key.clone(),
            secret_key: self.secret_key,
            blinding_factor: blinding,
        }
    }
}

impl<G> Display for ProverNodeData<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        let sk_marker = self
            .secret_key
            .to_string()
            .chars()
            .take(8)
            .collect::<String>()
            + "...";

        write!(
            f,
            "pk: {}, co_pk: {}, sk: {}",
            pk_marker, co_pk_marker, sk_marker
        )
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierNodeData<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
}

impl<G> Display for VerifierNodeData<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        write!(f, "pk: {}, co_pk: {}", pk_marker, co_pk_marker)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct R1CSProof(pub BPR1CSProof);

impl PartialEq for R1CSProof {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for R1CSProof {}

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

        Ok(R1CSProof(proof))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CompressedRistretto(pub DalekCompressedRistretto);

#[derive(Clone)]
pub enum UpdateProof {
    BranchProof((Vec<R1CSProof>, Vec<CompressedRistretto>)),
    AggregatedProof(AggregatedTreeProof),
}

impl CanonicalSerialize for UpdateProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            UpdateProof::BranchProof(branch_proof) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                branch_proof.serialize_with_mode(&mut writer, compress)?;
            }
            UpdateProof::AggregatedProof(tree_proof) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                tree_proof.serialize_with_mode(&mut writer, compress)?;
            }
        }

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match self {
            UpdateProof::BranchProof(branch_proof) => 1 + branch_proof.serialized_size(compress),
            UpdateProof::AggregatedProof(tree_proof) => 1 + tree_proof.serialized_size(compress),
        }
    }
}

impl ark_serialize::Valid for UpdateProof {
    fn check(&self) -> Result<(), SerializationError> {
        // Validity check is performed during deserialization
        Ok(())
    }
}

impl CanonicalDeserialize for UpdateProof {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        // Read variant tag
        let variant = u8::deserialize_with_mode(&mut reader, compress, validate)?;

        match variant {
            0 => {
                let proof: (Vec<R1CSProof>, Vec<CompressedRistretto>) =
                    <(Vec<R1CSProof>, Vec<CompressedRistretto>)>::deserialize_with_mode(
                        &mut reader,
                        compress,
                        validate,
                    )?;
                Ok(UpdateProof::BranchProof(proof))
            }
            1 => {
                // Member variant
                let proof =
                    AggregatedTreeProof::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(UpdateProof::AggregatedProof(proof))
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ArtProof {
    pub(crate) update_proof: UpdateProof,
    pub(crate) eligibility_proof: EligibilityProof,
}

impl PartialEq for CompressedRistretto {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for CompressedRistretto {}

impl CanonicalSerialize for CompressedRistretto {
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

impl ark_serialize::Valid for CompressedRistretto {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for CompressedRistretto {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        // Deserialize the proof
        let proof_len = u32::deserialize_compressed(&mut reader)? as usize;
        let mut proof_bytes = vec![0u8; proof_len];
        reader.read_exact(&mut proof_bytes)?;
        let point = DalekCompressedRistretto::from_slice(&proof_bytes)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

        Ok(CompressedRistretto(point))
    }
}

/// Estimate the number of generators needed for the given depth
pub(crate) fn estimate_bp_gens(height: usize, leaves: usize, dh_ver: u8) -> usize {
    let eps = 5;

    let scalar_mul_complexity = match dh_ver {
        1 => 1521,
        2 => 1268,
        _ => 0,
    };

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

    1 << log2(leaves * scalar_mul_complexity + height * (level_complexity + eps))
}

impl<'a> ZeroArtProverContext<'a> {
    pub(crate) fn prove_level(
        &self,
        bp_gens: &BulletproofGens,
        level: usize,
        node: &ProverNodeDataWithBlinding<CortadoAffine>,
        next_node: &ProverNodeDataWithBlinding<CortadoAffine>,
    ) -> Result<(R1CSProof, (CompressedRistretto, CompressedRistretto)), R1CSError> {
        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut prover = Prover::new(&self.engine.pc_gens, &mut transcript);
        let (a_commitment, var_a) = prover.commit(
            node.secret_key.into_scalar(),
            node.blinding_factor,
        );
        let (ab_commitment, var_ab) = prover.commit(
            next_node.secret_key.into_scalar(),
            next_node.blinding_factor,
        );
        let λ_a_i = AllocatedScalar::new(var_a, Some(node.secret_key.into_scalar()));
        let λ_a_next = AllocatedScalar::new(var_ab, Some(next_node.secret_key.into_scalar()));

        art_level_gadget(
            self.engine.options.scalar_mul_gadget_ver,
            &mut prover,
            level,
            λ_a_i,
            λ_a_next,
            node.public_key,
            next_node.public_key,
            node.co_public_key.unwrap(),
        )?;

        Ok((
            R1CSProof(prover.prove(&bp_gens)?),
            (
                CompressedRistretto(a_commitment),
                CompressedRistretto(ab_commitment),
            ),
        ))
    }

    pub(crate) fn prove_branch_single_threaded(
        &self,
        branch_nodes: &Vec<ProverNodeDataWithBlinding<CortadoAffine>>,
    ) -> Result<(Vec<R1CSProof>, Vec<CompressedRistretto>), R1CSError> {
        let start = Instant::now();
        let k = branch_nodes.len() - 1;
        let bp_gens = BulletproofGens::new(
            estimate_bp_gens(
                branch_nodes.len() - 1,
                1,
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        );
        let mut commitments = Vec::new();
        let mut vars = Vec::new();
        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut prover = Prover::new(&self.engine.pc_gens, &mut transcript);

        for i in 0..k + 1 {
            let node = &branch_nodes[i];
            let (a_commitment, var_a) = prover.commit(
                node.secret_key.into_scalar(),
                node.blinding_factor,
            );
            commitments.push(a_commitment);
            vars.push(AllocatedScalar::new(
                var_a,
                Some(node.secret_key.into_scalar()),
            ));
        }

        for i in 0..k {
            let node = &branch_nodes[i];
            let next_node = &branch_nodes[i + 1];
            art_level_gadget(
                self.engine.options.scalar_mul_gadget_ver,
                &mut prover,
                i,
                vars[i],
                vars[i + 1],
                node.public_key,
                next_node.public_key,
                node.co_public_key.unwrap(),
            )?;
        }
        let m = prover.metrics();
        let proof = prover.prove(&bp_gens)?;

        debug!(
            "prove_branch_single_threaded for depth {} proving time: {:?}, proof_len: {}, gadget size: {:?}",
            k,
            start.elapsed(),
            proof.to_bytes().len(),
            m.multipliers
        );
        Ok((
            vec![R1CSProof(proof)],
            commitments
                .iter()
                .map(|c| CompressedRistretto(*c))
                .collect(),
        ))
    }

    pub(crate) fn prove_branch_multi_threaded(
        &self,
        branch_nodes: &Vec<ProverNodeDataWithBlinding<CortadoAffine>>,
    ) -> Result<(Vec<R1CSProof>, Vec<CompressedRistretto>), R1CSError> {
        let start = Instant::now();
        let k = branch_nodes.len() - 1;
        let bp_gens = Arc::new(BulletproofGens::new(
            estimate_bp_gens(1, 1, self.engine.options.scalar_mul_gadget_ver),
            1,
        ));

        let (proofs, commitments): (
            Vec<R1CSProof>,
            Vec<(CompressedRistretto, CompressedRistretto)>,
        ) = std::thread::scope(|s| {
            (0..k)
                .map(|i| {
                    let bp_gens = bp_gens.clone();
                    let node = branch_nodes[i].clone();
                    let next_node = branch_nodes[i + 1].clone();

                    s.spawn(move || self.prove_level(&bp_gens, i, &node, &next_node))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Result<Vec<_>, R1CSError>>()
        })?
        .into_iter()
        .unzip();
        let commitments = commitments
            .iter()
            .map(|(a_commitment, _)| a_commitment.clone())
            //.chain(std::iter::once(commitments.last().unwrap().1.clone()))
            .chain(commitments.last().map(|last| last.1.clone()).into_iter())
            .collect::<Vec<_>>();

        debug!(
            "prove_branch_multi_threaded for depth {k} proving time: {:?}, proof_len: {}",
            start.elapsed(),
            proofs.iter().map(|x| x.0.to_bytes().len()).sum::<usize>()
        );

        Ok((proofs, commitments))
    }

    pub(crate) fn prove_branch(
        &self,
        branch_nodes: &Vec<ProverNodeDataWithBlinding<CortadoAffine>>,
    ) -> Result<(Vec<R1CSProof>, Vec<CompressedRistretto>), R1CSError> {
        match self.engine.options.multi_threaded {
            true => self.prove_branch_multi_threaded(branch_nodes),
            false => self.prove_branch_single_threaded(branch_nodes),
        }
    }

    /// Prove the operation
    pub(crate) fn prove_singular<R>(
        &self,
        branch_nodes: &Vec<ProverNodeData<CortadoAffine>>,
        rng: &mut R,
    ) -> Result<ArtProof, ZKError>
    where
        R: CryptoRngCore,
    {
        let branch_nodes = branch_nodes
            .iter()
            .map(|node| node.with_blinding(Scalar::random(rng)))
            .collect::<Vec<_>>();

        match self.engine.options.multi_threaded {
            false => Ok(ArtProof {
                update_proof: UpdateProof::BranchProof(self.prove_branch(&branch_nodes)?),
                eligibility_proof: self.prove_eligibility()?,
            }),
            true => std::thread::scope(|s| {
                let branch_handle = s.spawn(|| self.prove_branch(&branch_nodes));
                let eligibility_handle = s.spawn(|| self.prove_eligibility());

                let branch_proof = branch_handle.join().unwrap()?;
                let eligibility_proof = eligibility_handle.join().unwrap()?;

                Ok(ArtProof {
                    update_proof: UpdateProof::BranchProof(branch_proof),
                    eligibility_proof,
                })
            }),
        }
    }
}

impl<'a> ZeroArtVerifierContext<'a> {
    pub(crate) fn verify_level(
        &self,
        bp_gens: &BulletproofGens,
        level: usize,
        node: &VerifierNodeData<CortadoAffine>,
        next_node: &VerifierNodeData<CortadoAffine>,
        (proof, (commitment_i, commitment_next)): (
            R1CSProof,
            (CompressedRistretto, CompressedRistretto),
        ),
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut verifier = Verifier::new(&mut transcript);
        let var_a = verifier.commit(commitment_i.0);
        let var_ab = verifier.commit(commitment_next.0);
        let λ_a_i = AllocatedScalar::new(var_a, None);
        let λ_a_next = AllocatedScalar::new(var_ab, None);

        art_level_gadget(
            self.engine.options.scalar_mul_gadget_ver,
            &mut verifier,
            level,
            λ_a_i,
            λ_a_next,
            node.public_key,
            next_node.public_key,
            node.co_public_key.unwrap(),
        )
        .and_then(|_| verifier.verify(&proof.0, &self.engine.pc_gens, &bp_gens))
    }

    pub(crate) fn verify_branch_single_threaded(
        &self,
        (proofs, commitments): &(Vec<R1CSProof>, Vec<CompressedRistretto>),
        branch_nodes: &Vec<VerifierNodeData<CortadoAffine>>,
    ) -> Result<(), R1CSError> {
        let start = Instant::now();
        let k = branch_nodes.len() - 1;
        let bp_gens = BulletproofGens::new(
            estimate_bp_gens(
                branch_nodes.len() - 1,
                1,
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        );

        assert!(k == 0 || (k == commitments.len() - 1), "length mismatch");
        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut verifier = Verifier::new(&mut transcript);
        let mut vars = Vec::new();
        for i in 0..k + 1 {
            let var_a = verifier.commit(commitments[i].0);
            vars.push(AllocatedScalar::new(var_a, None));
        }

        for i in 0..k {
            let node = &branch_nodes[i];
            let next_node = &branch_nodes[i + 1];
            art_level_gadget(
                self.engine.options.scalar_mul_gadget_ver,
                &mut verifier,
                i,
                vars[i],
                vars[i + 1],
                node.public_key,
                next_node.public_key,
                node.co_public_key.unwrap(),
            )?;
        }
        verifier.verify(&proofs[0].0, &self.engine.pc_gens, &bp_gens)?;

        debug!(
            "verify_branch_single_threaded for depth {} verification time: {:?}",
            k,
            start.elapsed()
        );

        Ok(())
    }

    pub(crate) fn verify_branch_multi_threaded(
        &self,
        (proofs, commitments): &(Vec<R1CSProof>, Vec<CompressedRistretto>),
        branch_nodes: &Vec<VerifierNodeData<CortadoAffine>>,
    ) -> Result<(), R1CSError> {
        let start = Instant::now();
        let k = branch_nodes.len() - 1;
        let bp_gens = BulletproofGens::new(
            estimate_bp_gens(1, 1, self.engine.options.scalar_mul_gadget_ver),
            1,
        );

        assert!(k == 0 || (k == commitments.len() - 1), "length mismatch");
        let bp_gens = Arc::new(bp_gens.clone());
        let bp_gens = Arc::clone(&bp_gens);

        std::thread::scope(|s| {
            (0..k)
                .map(|i| {
                    let bp_gens = bp_gens.clone();
                    let node = branch_nodes[i].clone();
                    let next_node = branch_nodes[i + 1].clone();
                    let proof_i = proofs[i].clone();
                    let commitment_i = commitments[i].clone();
                    let commitment_next = commitments[i + 1].clone();

                    s.spawn(move || {
                        self.verify_level(
                            &bp_gens,
                            i,
                            &node,
                            &next_node,
                            (proof_i, (commitment_i, commitment_next)),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Result<(), _>>()
        })
        .and_then(|_| {
            debug!(
                "verify_branch_multi_threaded for depth {} verification time: {:?}",
                k,
                start.elapsed()
            );

            Ok(())
        })
    }

    pub(crate) fn verify_branch(
        &self,
        branch_proof: &(Vec<R1CSProof>, Vec<CompressedRistretto>),
        branch_nodes: &Vec<VerifierNodeData<CortadoAffine>>,
    ) -> Result<(), R1CSError> {
        match self.engine.options.multi_threaded {
            true => self.verify_branch_multi_threaded(branch_proof, branch_nodes),
            false => self.verify_branch_single_threaded(branch_proof, branch_nodes),
        }
    }

    /// Verify the proof of an operation
    pub(crate) fn verify_singular(
        &self,
        proof: &ArtProof,
        branch_nodes: &Vec<VerifierNodeData<CortadoAffine>>,
    ) -> Result<(), ZKError> {
        let branch_proof = if let UpdateProof::BranchProof(ref branch_proof) = proof.update_proof {
            branch_proof
        } else {
            return Err(ZKError::InvalidProofType);
        };
        match self.engine.options.multi_threaded {
            false => {
                self.verify_branch(branch_proof, branch_nodes)?;
                self.verify_eligibility(&proof.eligibility_proof)?;
                Ok(())
            }
            true => std::thread::scope(|s| {
                let branch_handle = s.spawn(|| self.verify_branch(branch_proof, branch_nodes));
                let eligibility_handle =
                    s.spawn(|| self.verify_eligibility(&proof.eligibility_proof));

                branch_handle.join().unwrap()?;
                eligibility_handle.join().unwrap()?;

                Ok(())
            }),
        }
    }
}

/// generate an ART update proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself), additional keypairs (s, R),
/// and branch node data
pub fn art_prove(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data

    branch_nodes: &Vec<ProverNodeData<CortadoAffine>>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    s: Vec<cortado::Fr>,   // auxiliary 𝔾_1 secrets
) -> Result<ArtProof, ZKError> {
    let start = Instant::now();

    // Create prover and verifier engines
    let prover_engine = ZeroArtProverEngine::new(basis.clone(), ZeroArtEngineOptions::default());

    // Set up eligibility artefact for prover
    let eligibility = EligibilityArtefact::Member((s[0], R[0]));

    // Create prover context
    let prover_context = prover_engine.new_context(eligibility);

    // Generate proof
    let proof = prover_context.prove_singular(&branch_nodes, &mut thread_rng())?;

    debug!("art_prove time: {:?}", start.elapsed());

    Ok(proof)
}

/// verify an ART proof provided basis, auxiliary data ad(typically a hash of the ART or the ART itself),
/// additional public keys R, and branch node data
pub fn art_verify(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data

    branch_nodes: &Vec<VerifierNodeData<CortadoAffine>>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    proof: ArtProof,
) -> Result<(), ZKError> {
    let start = Instant::now();

    let verifier_engine = ZeroArtVerifierEngine::new(basis, ZeroArtEngineOptions::default());

    // Set up eligibility requirement for verifier
    let eligibility_req = EligibilityRequirement::Member(R[0]);

    // Create verifier context
    let verifier_context = verifier_engine.new_context(eligibility_req).with_associated_data(ad);

    // Verify proof
    verifier_context.verify_singular(&proof, &branch_nodes)?;

    debug!("art_verify time: {:?}", start.elapsed());

    Ok(())
}

#[cfg(test)]
mod tests {
    use zkp::{ProofError, toolbox::dalek_ark::ristretto255_to_ark};

    use crate::engine::ZeroArtEngineOptions;

    use super::*;

    /// generate random witness for $\mathcal{R}_{\mathsf{upd}}$
    fn random_witness_gen(k: u32) -> Vec<ProverNodeData<CortadoAffine>> {
        let start = Instant::now();
        let mut blinding_rng = rand::thread_rng();
        let mut nodes = Vec::new();
        let mut λ_a: cortado::Fr = blinding_rng.r#gen();

        let r: cortado::Fr = blinding_rng.r#gen();
        let mut q_b = (CortadoAffine::generator() * r).into_affine();
        // First node
        nodes.push(ProverNodeData {
            secret_key: λ_a,
            public_key: (CortadoAffine::generator() * λ_a).into_affine(),
            co_public_key: Some(q_b),
        });

        for i in 0..k {
            let R = (q_b * λ_a).into_affine();
            λ_a = R.x().unwrap().into_bigint().into();

            let r: cortado::Fr = blinding_rng.r#gen();
            q_b = (CortadoAffine::generator() * r).into_affine();
            // Create next node
            nodes.push(ProverNodeData {
                secret_key: λ_a,
                public_key: (CortadoAffine::generator() * λ_a).into_affine(),
                co_public_key: if i != k - 1 { Some(q_b) } else { None },
            });
        }

        debug!(
            "random_witness_gen for depth {} took {:?}",
            k,
            start.elapsed()
        );
        nodes
    }

    fn art_roundtrip(k: u32) -> Result<(), ZKError> {
        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );

        let branch_nodes = random_witness_gen(k);

        // Create prover's secrets for eligibility
        let s = cortado::Fr::rand(&mut thread_rng());
        let R = (G_1 * s).into_affine();

        // important: in real app verifier nodes should be generated from the current state of ART(co_public_keys) and the updating branch
        let verifier_nodes: Vec<VerifierNodeData<CortadoAffine>> = branch_nodes
            .iter()
            .map(|node| VerifierNodeData {
                public_key: node.public_key,
                co_public_key: node.co_public_key,
            })
            .collect();

        // Set up test data
        let ad = &[0x72, 0x75, 0x73, 0x73, 0x69, 0x61, 0x64, 0x69, 0x65];

        // Create prover and verifier engines
        let prover_engine =
            ZeroArtProverEngine::new(basis.clone(), ZeroArtEngineOptions::default());
        let verifier_engine = ZeroArtVerifierEngine::new(basis, ZeroArtEngineOptions::default());

        // Set up eligibility artefact for prover
        let eligibility = EligibilityArtefact::Owner((s, R));

        // Create prover context
        let prover_context = prover_engine.new_context(eligibility).with_associated_data(ad);

        // Generate proof
        let proof = prover_context.prove_singular(&branch_nodes, &mut thread_rng())?;

        // Set up eligibility requirement for verifier
        let eligibility_req = EligibilityRequirement::Previleged((R, vec![]));

        // Create verifier context
        let verifier_context = verifier_engine.new_context(eligibility_req).with_associated_data(ad);

        // Verify proof
        verifier_context.verify_singular(&proof, &verifier_nodes)
    }

    #[test]
    fn test_art_roundtrip() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();

        for i in 0..16 {
            art_roundtrip(i).unwrap();
        }
    }
}
