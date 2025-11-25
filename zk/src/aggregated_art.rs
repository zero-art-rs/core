#![allow(non_snake_case)]
use ark_ec::{AffineRepr, CurveGroup, scalar_mul};
use serde::de;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

use crate::art::{ArtProof, CompressedRistretto, ProverNodeData, R1CSProof, UpdateProof, VerifierNodeData, estimate_bp_gens, ProverNodeDataWithBlinding};
use crate::dh::art_level_gadget;
use crate::eligibility::EligibilityRequirement;
use crate::engine::{
    ZeroArtEngineOptions, ZeroArtProverContext, ZeroArtProverEngine, ZeroArtVerifierContext,
    ZeroArtVerifierEngine,
};
use crate::errors::ZKError;
use crate::gadgets::r1cs_utils::AllocatedScalar;

use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::Scalar;
use cortado::{self, CortadoAffine, ToScalar};
use merlin::Transcript;
use rand::thread_rng;
use rand_core::CryptoRngCore;
use tracing::debug;

use tree_ds::{prelude::Node, prelude::TraversalStrategy, prelude::Tree};
use zkp::CompactProof;
use zkp::toolbox::{
    SchnorrCS, cross_dleq::PedersenBasis, dalek_ark::ark_to_ristretto255,
    prover::Prover as SigmaProver, verifier::Verifier as SigmaVerifier,
};

/// aggregation tree for the prover
pub type ProverAggregationTree<G> = Tree<u64, ProverNodeData<G>>;
pub(crate) type ProverAggregationTreeWithBlinding<G> = Tree<u64, ProverNodeDataWithBlinding<G>>;

/// aggregation tree for the verifier
pub type VerifierAggregationTree<G> = Tree<u64, VerifierNodeData<G>>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatedTreeProof(Tree<u64, (Option<R1CSProof>, CompressedRistretto)>);

/// Initialize an empty aggregated proof tree
impl From<&ProverAggregationTreeWithBlinding<CortadoAffine>> for AggregatedTreeProof {
    fn from(tree: &ProverAggregationTreeWithBlinding<CortadoAffine>) -> Self {
        let mut new_tree = Tree::new(Some("aggregated_proof"));
        for node in tree.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            let parent_id = node.get_parent_id().ok().flatten();
            new_tree
                .add_node(Node::new(node_id, None), parent_id.as_ref())
                .unwrap();
        }
        AggregatedTreeProof(new_tree)
    }
}

/// Convert aggregated proof tree to an empty verifier aggregation public tree (needs to be populated after that)
impl From<&AggregatedTreeProof> for VerifierAggregationTree<CortadoAffine> {
    fn from(proof: &AggregatedTreeProof) -> Self {
        let mut new_tree = Tree::new(Some("verifier_aggregation_tree"));
        for node in proof.0.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            let parent_id = node.get_parent_id().ok().flatten();
            new_tree
                .add_node(Node::new(node_id, None), parent_id.as_ref())
                .unwrap();
        }
        new_tree
    }
}

impl CanonicalSerialize for AggregatedTreeProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        let serialized =
            postcard::to_allocvec(&self.0).map_err(|_| SerializationError::InvalidData)?;
        (self.serialized_size(compress) as u32).serialize_with_mode(&mut writer, compress)?;
        writer.write_all(&serialized)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        postcard::to_allocvec(&self.0).map_or(0, |v| v.len()) // check if this is efficient
    }
}

impl ark_serialize::Valid for AggregatedTreeProof {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for AggregatedTreeProof {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let proof_len = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let mut buf = vec![0u8; proof_len];

        reader
            .read_exact(&mut buf)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        let tree: Tree<u64, (Option<R1CSProof>, CompressedRistretto)> = postcard::from_bytes(&buf)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        Ok(AggregatedTreeProof(tree))
    }
}

impl<'a> ZeroArtProverContext<'a> {
    pub(crate) fn prove_tree_single_threaded(
        &self,
        aggregated_tree: &ProverAggregationTreeWithBlinding<CortadoAffine>,
    ) -> Result<AggregatedTreeProof, ZKError> {
        let start = Instant::now();
        let bp_gens = BulletproofGens::new(
            estimate_bp_gens(
                aggregated_tree.get_nodes().len() - 1,       // number of edges
                (aggregated_tree.get_nodes().len() + 1) / 2, // number of leaves (presuming binary tree)
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        );
        let aggregated_proof = AggregatedTreeProof::from(aggregated_tree);
        let root_id = aggregated_tree
            .get_root_node()
            .ok_or(ZKError::InvalidAggregation)?
            .get_node_id()
            .map_err(|_| ZKError::InvalidAggregation)?;

        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut prover = Prover::new(&self.engine.pc_gens, &mut transcript);
        for node_id in aggregated_tree
            .traverse(&root_id, TraversalStrategy::PreOrder)
            .map_err(|_| ZKError::InvalidAggregation)?
        {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node
                .get_parent_id()
                .map_err(|_| ZKError::InvalidAggregation)?;

            if let Some(parent_id) = parent_id {
                let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                let node_data = node
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .unwrap();
                let parent_data = parent
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .unwrap();

                let λ_a_i = node_data.secret_key.into_scalar();
                let b_i = node_data.blinding_factor;
                let λ_a_next = parent_data.secret_key.into_scalar();
                let b_next = parent_data.blinding_factor;
                let Q_a_i = node_data.public_key.clone();
                let Q_ab_i = parent_data.public_key.clone();
                let Q_b_i = node_data.co_public_key.unwrap().clone();
                let level = node.get_children_ids().unwrap().len();

                let (a_commitment, var_a) = prover.commit(λ_a_i, b_i);
                let (ab_commitment, var_ab) = prover.commit(λ_a_next, b_next);
                let λ_a_i = AllocatedScalar::new(var_a, Some(λ_a_i));
                let λ_a_next = AllocatedScalar::new(var_ab, Some(λ_a_next));

                art_level_gadget(
                    self.engine.options.scalar_mul_gadget_ver,
                    &mut prover,
                    level,
                    λ_a_i,
                    λ_a_next,
                    Q_a_i,
                    Q_ab_i,
                    Q_b_i,
                )?;

                if parent_id == root_id {
                    aggregated_proof
                        .0
                        .get_node_by_id(&parent_id)
                        .unwrap()
                        .update_value(|x| *x = Some((None, CompressedRistretto(ab_commitment))))
                        .map_err(|_| ZKError::InvalidAggregation)?;
                }
                aggregated_proof
                    .0
                    .get_node_by_id(&node_id)
                    .unwrap()
                    .update_value(|x| *x = Some((None, CompressedRistretto(a_commitment))))
                    .map_err(|_| ZKError::InvalidAggregation)?;
            }
        }
        let proof = prover.prove(&bp_gens)?;
        aggregated_proof
            .0
            .get_node_by_id(&root_id)
            .unwrap()
            .update_value(|x| {
                if let Some(x) = x.as_mut() {
                    *x = (Some(R1CSProof(proof)), x.1.clone());
                }
            })
            .unwrap(); // place whole proof in the root node
        let proof_len = aggregated_proof.serialized_size(Compress::Yes);
        debug!(
            "prove_tree_single_threaded for {} tree nodes proving time: {:?}, proof_len: {}",
            aggregated_tree.get_nodes().len(),
            start.elapsed(),
            proof_len
        );
        Ok(aggregated_proof)
    }

    pub(crate) fn prove_tree_multi_threaded(
        &self,
        aggregated_tree: &ProverAggregationTreeWithBlinding<CortadoAffine>,
    ) -> Result<AggregatedTreeProof, ZKError> {
        let start = Instant::now();
        let bp_gens = Arc::new(BulletproofGens::new(
            estimate_bp_gens(
                1, // number of edges
                1, // number of leaves (presuming binary tree)
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        ));
        let aggregated_proof = AggregatedTreeProof::from(aggregated_tree);

        let root_id = aggregated_tree
            .get_root_node()
            .ok_or(ZKError::InvalidAggregation)?
            .get_node_id()
            .map_err(|_| ZKError::InvalidAggregation)?;
        let k = aggregated_tree.get_nodes().len() - 1; // number of edges

        // Using scope to ensure all threads complete before function returns
        std::thread::scope(|s| {
            let proofs =
                aggregated_tree
                    .traverse(&root_id, TraversalStrategy::PreOrder)
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .iter()
                    .skip(1) // skip root node
                    .map(|node_id| {
                        let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
                        let parent = node
                            .get_parent_id()?
                            .map(|x| aggregated_tree.get_node_by_id(&x).unwrap())
                            .unwrap();

                        let node_data = node.get_value()?.unwrap();
                        let parent_data = parent.get_value()?.unwrap();
                        let level = node.get_children_ids()?.len(); // for leaves level is 0
                        let bp_gens = bp_gens.clone();

                        Ok(s.spawn(move || {
                            self.prove_level(&bp_gens, level, &node_data, &parent_data)
                        }))
                    })
                    .collect::<tree_ds::prelude::Result<Vec<_>>>()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .collect::<Result<Vec<_>, R1CSError>>()?;

            for (node_id, (proof, (comm, comm_next))) in aggregated_proof
                .0
                .traverse(&root_id, TraversalStrategy::PreOrder)
                .map_err(|_| ZKError::InvalidAggregation)?
                .iter()
                .skip(1)
                .zip(proofs)
            {
                let node = aggregated_proof.0.get_node_by_id(&node_id).unwrap();
                let parent = node
                    .get_parent_id()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .map(|x| aggregated_proof.0.get_node_by_id(&x).unwrap())
                    .unwrap();
                node.update_value(|x| *x = Some((Some(proof), comm)))
                    .map_err(|_| ZKError::InvalidAggregation)?;
                if parent
                    .get_node_id()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    == root_id
                {
                    parent
                        .update_value(|x| *x = Some((None, comm_next)))
                        .map_err(|_| ZKError::InvalidAggregation)?;
                }
            }
            debug!(
                "prove_tree_multi_threaded for depth {k} proving time: {:?}, proof_len: {}",
                start.elapsed(),
                aggregated_proof.serialized_size(Compress::Yes)
            );
            Ok(aggregated_proof)
        })
    }

    pub(crate) fn prove_tree(
        &self,
        aggregated_tree: &ProverAggregationTreeWithBlinding<CortadoAffine>,
    ) -> Result<AggregatedTreeProof, ZKError> {
        match self.engine.options.multi_threaded {
            true => self.prove_tree_multi_threaded(aggregated_tree),
            false => self.prove_tree_single_threaded(aggregated_tree),
        }
    }

    /// Prove the aggregated operations
    pub(crate) fn prove_aggregated<R>(
        &self,
        aggregated_tree: &ProverAggregationTree<CortadoAffine>,
        rng: &mut R,
    ) -> Result<ArtProof, ZKError>
    where
        R: CryptoRngCore,
    {
        let root_id = aggregated_tree
            .get_root_node()
            .ok_or(ZKError::InvalidAggregation)?
            .get_node_id()
            .map_err(|_| ZKError::InvalidAggregation)?;
        let mut aggregated_tree_with_blinding = Tree::new(Some("aggregated_proof"));
        for node_id in aggregated_tree
            .traverse(&root_id, TraversalStrategy::PreOrder)
            .map_err(|_| ZKError::InvalidAggregation)?
        {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node
                .get_parent_id()
                .map_err(|_| ZKError::InvalidAggregation)?;
            let node_value = node
                .get_value()
                .map_err(|_| ZKError::InvalidAggregation)?
                .ok_or(ZKError::InvalidAggregation)?;
            let new_node = Node::new(node_id, Some(node_value.with_blinding(Scalar::random(rng))));
            aggregated_tree_with_blinding
                .add_node(new_node, parent_id.as_ref())
                .map_err(|_| ZKError::InvalidAggregation)?;
        }

        match self.engine.options.multi_threaded {
            false => Ok(ArtProof {
                update_proof: UpdateProof::AggregatedProof(self.prove_tree(&aggregated_tree_with_blinding)?),
                eligibility_proof: self.prove_eligibility()?,
            }),
            true => std::thread::scope(|s| {
                let branch_handle = s.spawn(|| self.prove_tree(&aggregated_tree_with_blinding));
                let eligibility_handle = s.spawn(|| self.prove_eligibility());

                let update_proof = branch_handle.join().unwrap()?;
                let eligibility_proof = eligibility_handle.join().unwrap()?;

                Ok(ArtProof {
                    update_proof: UpdateProof::AggregatedProof(update_proof),
                    eligibility_proof,
                })
            }),
        }
    }
}

impl<'a> ZeroArtVerifierContext<'a> {
    pub(crate) fn verify_tree_single_threaded(
        &self,
        aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
        proof_tree: &AggregatedTreeProof,
    ) -> Result<(), ZKError> {
        let start = Instant::now();
        let bp_gens = BulletproofGens::new(
            estimate_bp_gens(
                aggregated_tree.get_nodes().len() - 1,       // number of edges
                (aggregated_tree.get_nodes().len() + 1) / 2, // number of leaves (presuming binary tree)
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        );
        let mut transcript = Transcript::new(b"ARTGadget");
        transcript.append_message(b"ad", self.ad());
        let mut verifier = Verifier::new(&mut transcript);
        let root_id = aggregated_tree
            .get_root_node()
            .ok_or(ZKError::InvalidAggregation)?
            .get_node_id()
            .map_err(|_| ZKError::InvalidAggregation)?;

        for node_id in aggregated_tree
            .traverse(&root_id, TraversalStrategy::PreOrder)
            .map_err(|_| ZKError::InvalidAggregation)?
        {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node
                .get_parent_id()
                .map_err(|_| ZKError::InvalidAggregation)?;

            if let Some(parent_id) = parent_id {
                let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                let node_data = node
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .unwrap();
                let parent_data = parent
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?
                    .unwrap();

                let proof_node = proof_tree.0.get_node_by_id(&node_id).unwrap();
                let proof_parent = proof_tree.0.get_node_by_id(&parent_id).unwrap();
                let proof_node_data = proof_node
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?;
                let proof_parent_data = proof_parent
                    .get_value()
                    .map_err(|_| ZKError::InvalidAggregation)?;

                let Q_a_i = node_data.public_key.clone();
                let Q_b_i = node_data.co_public_key.unwrap().clone();
                let Q_ab_i = parent_data.public_key.clone();
                let (_, commitment_i) = proof_node_data.ok_or(ZKError::InvalidAggregation)?;
                let (_, commitment_next) = proof_parent_data.ok_or(ZKError::InvalidAggregation)?;
                let level = node.get_children_ids().unwrap().len();

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
                    Q_a_i,
                    Q_ab_i,
                    Q_b_i,
                )?;
            }
        }
        let proof = proof_tree
            .0
            .get_node_by_id(&root_id)
            .unwrap()
            .get_value()
            .map_err(|_| ZKError::InvalidAggregation)?
            .ok_or(ZKError::InvalidAggregation)?
            .0
            .ok_or(ZKError::InvalidAggregation)?;
        verifier.verify(&proof.0, &self.engine.pc_gens, &bp_gens)?;

        debug!(
            "verify_tree_single_threaded for {} tree nodes verification time: {:?}",
            aggregated_tree.get_nodes().len(),
            start.elapsed()
        );
        Ok(())
    }

    pub(crate) fn verify_tree_multi_threaded(
        &self,
        aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
        proof_tree: &AggregatedTreeProof,
    ) -> Result<(), ZKError> {
        let start = Instant::now();

        let bp_gens = Arc::new(BulletproofGens::new(
            estimate_bp_gens(
                1, // number of edges
                1, // number of leaves (presuming binary tree)
                self.engine.options.scalar_mul_gadget_ver,
            ),
            1,
        ));

        let root_id = aggregated_tree
            .get_root_node()
            .ok_or(ZKError::InvalidAggregation)?
            .get_node_id()
            .map_err(|_| ZKError::InvalidAggregation)?;

        // Using scope to ensure all threads complete before function returns
        std::thread::scope(|s| {
            aggregated_tree
                .traverse(&root_id, TraversalStrategy::PreOrder)
                .map_err(|_| ZKError::InvalidAggregation)?
                .iter()
                .skip(1) // Skip the root node
                .map(|node_id| {
                    let node = aggregated_tree.get_node_by_id(node_id).unwrap();
                    let parent_id = node.get_parent_id()?.unwrap();
                    let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                    let node_data = node.get_value()?.unwrap();
                    let parent_data = parent.get_value()?.unwrap();

                    let proof_node = proof_tree.0.get_node_by_id(node_id).unwrap();
                    let proof_parent = proof_tree.0.get_node_by_id(&parent_id).unwrap();

                    let (proof, commitment_i) = proof_node.get_value()?.unwrap();
                    let (_, commitment_next) = proof_parent.get_value()?.unwrap();

                    let level = node.get_children_ids()?.len();
                    let bp_gens = bp_gens.clone();

                    Ok(s.spawn(move || {
                        self.verify_level(
                            &bp_gens,
                            level,
                            &node_data,
                            &parent_data,
                            (
                                proof.ok_or(R1CSError::VerificationError)?,
                                (commitment_i.clone(), commitment_next.clone()),
                            ),
                        )
                    }))
                })
                .collect::<tree_ds::prelude::Result<Vec<_>>>()
                .map_err(|_| ZKError::InvalidAggregation)?
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Result<Vec<_>, R1CSError>>()?;

            debug!(
                "verify_tree_multi_threaded for depth {} verification time: {:?}",
                aggregated_tree.get_nodes().len() - 1,
                start.elapsed()
            );
            Ok(())
        })
    }

    pub(crate) fn verify_tree(
        &self,
        aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
        proof_tree: &AggregatedTreeProof,
    ) -> Result<(), ZKError> {
        match self.engine.options.multi_threaded {
            true => self.verify_tree_multi_threaded(aggregated_tree, proof_tree),
            false => self.verify_tree_single_threaded(aggregated_tree, proof_tree),
        }
    }

    /// Verify the proof of an operation
    pub(crate) fn verify_aggregated(
        &self,
        aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
        proof: &ArtProof,
    ) -> Result<(), ZKError> {
        let aggregated_proof =
            if let UpdateProof::AggregatedProof(ref aggregated_proof) = proof.update_proof {
                aggregated_proof
            } else {
                return Err(ZKError::InvalidProofType);
            };
        match self.engine.options.multi_threaded {
            false => {
                self.verify_tree(aggregated_tree, aggregated_proof)?;
                self.verify_eligibility(&proof.eligibility_proof)?;
                Ok(())
            }
            true => std::thread::scope(|s| {
                let update_handle = s.spawn(|| self.verify_tree(aggregated_tree, aggregated_proof));
                let eligibility_handle =
                    s.spawn(|| self.verify_eligibility(&proof.eligibility_proof));

                update_handle.join().unwrap()?;
                eligibility_handle.join().unwrap()?;

                Ok(())
            }),
        }
    }
}
/// generate an aggregated ART update proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself), additional public keys R,
/// path public keys Q_a, reciprocal co-path public keys Q_b, ART path secrets λ_a, auxiliary 𝔾_1 secrets s, and blinding factors for λ_a
pub fn art_aggregated_prove(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    aggregated_tree: &ProverAggregationTree<CortadoAffine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    s: Vec<cortado::Fr>,   // auxiliary 𝔾_1 secrets
) -> Result<ArtProof, ZKError> {
    let start = Instant::now();
    let engine = ZeroArtProverEngine::new(basis, ZeroArtEngineOptions::default());
    let context = engine
        .new_context(crate::eligibility::EligibilityArtefact::Member((s[0], R[0])))
        .with_associated_data(ad);
    let proof = context.prove_aggregated(aggregated_tree, &mut thread_rng());
    debug!("art_aggregated_prove time: {:?}", start.elapsed());
    proof
}

/// verify an ART proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself),
/// additional public keys R, user path Q_a, reciprocal co-path public keys Q_b, and the ART proof itself
pub fn art_aggregated_verify(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    proof: &ArtProof,
) -> Result<(), ZKError> {
    let start = Instant::now();
    let engine = ZeroArtVerifierEngine::new(basis, ZeroArtEngineOptions::default());
    let context = engine.new_context(EligibilityRequirement::Member(R[0])).with_associated_data(ad);
    let res = context.verify_aggregated(aggregated_tree, proof);
    debug!("art_aggregated_verify time: {:?}", start.elapsed());
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::poseidon_gadget::PADDING_CONST;
    use ark_ff::{PrimeField, UniformRand};
    use rand::{Rng, thread_rng};
    use serde::de;
    use std::fmt::Display;
    use std::hash::Hash;
    use tracing::trace;
    use tracing_subscriber::field::debug;
    use zkp::ProofError;
    use zkp::toolbox::dalek_ark::ristretto255_to_ark;

    fn convert_to_verifier_tree(
        tree: &ProverAggregationTree<CortadoAffine>,
    ) -> VerifierAggregationTree<CortadoAffine> {
        let mut verifier_tree = VerifierAggregationTree::new(Some("verifier_tree"));
        for node in tree.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            let parent_id = node.get_parent_id().ok().flatten();
            let node_data = node.get_value().unwrap().unwrap();

            verifier_tree
                .add_node(
                    Node::new(
                        node_id,
                        Some(VerifierNodeData {
                            public_key: node_data.public_key,
                            co_public_key: node_data.co_public_key,
                        }),
                    ),
                    parent_id.as_ref(),
                )
                .unwrap();
        }
        verifier_tree
    }

    fn compute_art(tree: &ProverAggregationTree<CortadoAffine>, leaf_id: u64) {
        let root_id = tree.get_root_node().unwrap().get_node_id().unwrap();
        let mut prev_node = tree.get_node_by_id(&leaf_id).unwrap();
        let mut node = tree
            .get_node_by_id(&prev_node.get_parent_id().unwrap().unwrap())
            .unwrap(); // skip the leaf
        loop {
            let prev_node_value = prev_node.get_value().unwrap().unwrap();

            // Compute the new secret key and public key for current node
            let R =
                (prev_node_value.co_public_key.unwrap() * prev_node_value.secret_key).into_affine();
            let new_secret_key = R.x().unwrap().into_bigint().into();
            let new_public_key = (CortadoAffine::generator() * new_secret_key).into_affine();
            node.update_value(|x| {
                if let Some(x) = x {
                    x.secret_key = new_secret_key;
                    x.public_key = new_public_key;
                }
            })
            .unwrap();

            // Move to parent
            let Some(parent_id) = node.get_parent_id().unwrap() else {
                break;
            };
            let parent_node = tree.get_node_by_id(&parent_id).unwrap();
            prev_node = node;
            node = parent_node;
            // update sibling's co_public_key
            let sibling_id = node
                .get_children_ids()
                .unwrap()
                .iter()
                .find(|&&x| x != prev_node.get_node_id().unwrap())
                .unwrap()
                .clone();
            tree.get_node_by_id(&sibling_id)
                .unwrap()
                .update_value(|x| {
                    if let Some(x) = x {
                        x.co_public_key = Some(new_public_key);
                    }
                })
                .unwrap();
            trace!("tree state for leaf {leaf_id}: {}", tree);
        }
    }

    fn generate_random_tree(k: u64) -> ProverAggregationTree<CortadoAffine> {
        let mut rng = &mut thread_rng();
        let mut tree = ProverAggregationTree::new(Some("test_prover_tree"));
        let root_sk = cortado::Fr::rand(&mut rng);
        let root_pk = (CortadoAffine::generator() * root_sk).into_affine();
        let root_id = 0;
        let root_node = Node::new(
            root_id,
            Some(ProverNodeData {
                public_key: root_pk,
                co_public_key: None,
                secret_key: root_sk,
            }),
        );
        tree.add_node(root_node, None).unwrap();

        let mut node_count: u64 = 1;

        // generation of random ART
        while node_count < k {
            for node_id in tree
                .traverse(&root_id, TraversalStrategy::PreOrder)
                .unwrap()
            {
                if node_count >= k {
                    break;
                }
                if let Some(node) = tree.get_node_by_id(&node_id) {
                    let node_value = node.get_value().unwrap().unwrap();
                    let children = node.get_children_ids().unwrap();
                    let added_leaf_id = match children.len() {
                        0 => {
                            let right_child_sk = rng.r#gen();
                            let right_child_pk =
                                (CortadoAffine::generator() * right_child_sk).into_affine();

                            // current node becomes a left child, add the new node to the right child
                            let left_child_node = Node::new(
                                node_count,
                                Some(ProverNodeData {
                                    secret_key: node_value.secret_key,
                                    public_key: node_value.public_key,
                                    co_public_key: Some(right_child_pk),
                                }),
                            );
                            tree.add_node(left_child_node, Some(&node_id)).unwrap();
                            node_count += 1;

                            let right_child_node = Node::new(
                                node_count,
                                Some(ProverNodeData {
                                    public_key: right_child_pk,
                                    co_public_key: Some(node_value.public_key),
                                    secret_key: right_child_sk,
                                }),
                            );
                            tree.add_node(right_child_node, Some(&node_id)).unwrap();
                            node_count += 1;
                            node_count - 1
                        }
                        2 => {
                            continue;
                        }
                        _ => panic!("Invalid number of children"),
                    };
                    compute_art(&tree, added_leaf_id);
                }
            }
            node_count += 1;
        }

        tree
    }

    fn aggregated_art_roundtrip(k: u64) {
        let mut rng = &mut thread_rng();

        // Initialize generators
        let G_1 = CortadoAffine::generator();
        let H_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            G_1,
            H_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );

        // Generate random auxiliary data
        let ad: Vec<u8> = vec![0x72, 0x75, 0x73, 0x73, 0x69, 0x61, 0x64, 0x69, 0x65];

        // Generate random tree with k nodes
        let prover_tree = generate_random_tree(k);
        trace!("Prover tree: {prover_tree}");

        // Generate auxiliary values
        let s = (0..2)
            .map(|_| cortado::Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let R = s
            .iter()
            .map(|&x| (G_1 * x).into_affine())
            .collect::<Vec<_>>();

        // Get verifier tree from prover tree (only for test, for real use case should use VerifierAggregationTree::from(&proof.Rδ)) and populating the tree from the current ART state
        let verifier_tree = convert_to_verifier_tree(&prover_tree);
        trace!("Verifier tree: {verifier_tree}");

        // Create proof
        let proof = art_aggregated_prove(basis.clone(), &ad, &prover_tree, R.clone(), s.clone())
            .expect("Proof generation should not fail");

        // Verify proof
        art_aggregated_verify(basis, &ad, &verifier_tree, R, &proof).unwrap();
    }

    #[test]
    fn test_aggregated_art() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();
        for i in 3..16 {
            aggregated_art_roundtrip(i);
        }
    }
}
