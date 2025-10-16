#![allow(non_snake_case)]
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

use crate::art::{estimate_bp_gens, CompressedRistretto, R1CSProof};
use crate::gadgets::r1cs_utils::AllocatedScalar;
use crate::dh::art_level_gadget;

use ark_ec::VariableBaseMSM;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use ark_std::log2;
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, R1CSProof as BPR1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use cortado::{self, CortadoAffine, FromScalar, Parameters, ToScalar};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use rand_core::{OsRng, le};
use serde::Serialize;
use tracing::{debug, info, instrument};

use tree_ds::{prelude::Tree, prelude::Node, prelude::TraversalStrategy};
use zkp::CompactProof;
use zkp::toolbox::{
    FromBytes, SchnorrCS, ToBytes,
    cross_dleq::{CrossDLEQProof, CrossDleqProver, CrossDleqVerifier, PedersenBasis},
    dalek_ark::{ark_to_ristretto255, ristretto255_to_ark, scalar_to_ark},
    prover::Prover as SigmaProver,
    verifier::Verifier as SigmaVerifier,
};

pub type ProverAggregationTree<G> = Tree<u64, ProverAggregatedNodeData<G>>;
pub type VerifierAggregationTree<G> = Tree<u64, VerifierAggregatedNodeData<G>>;

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct ProverAggregatedNodeData<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
    pub secret_key: G::ScalarField,
    pub blinding_factor: Scalar,
    pub marker: bool, // not used currently
}

impl<G> Display for ProverAggregatedNodeData<G>
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
            "pk: {}, co_pk: {}, sk: {}, marker: {}",
            pk_marker, co_pk_marker, sk_marker, self.marker
        )
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct VerifierAggregatedNodeData<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
    pub marker: bool, // not used currently
}

impl<G> Display for VerifierAggregatedNodeData<G>
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

        write!(
            f,
            "pk: {}, co_pk: {}, marker: {}",
            pk_marker, co_pk_marker, self.marker
        )
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregatedTreeProof (Tree<u64, (Option<R1CSProof>, CompressedRistretto)>);

/// Initialize an empty aggregated proof tree
impl From<&ProverAggregationTree<CortadoAffine>> for AggregatedTreeProof {
    fn from(tree: &ProverAggregationTree<CortadoAffine>) -> Self {
        let mut new_tree = Tree::new(Some("aggregated_proof"));
        for node in tree.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            let parent_id = node.get_parent_id().ok().flatten();
            new_tree.add_node(Node::new(node_id, None), parent_id.as_ref()).unwrap();
        }
        AggregatedTreeProof(new_tree)
    }
}

/// Convert aggregated proof tree to verifier aggregation public tree
impl From<&AggregatedTreeProof> for VerifierAggregationTree<CortadoAffine> {
    fn from(proof: &AggregatedTreeProof) -> Self {
        let mut new_tree = Tree::new(Some("verifier_aggregation_tree"));
        for node in proof.0.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            let parent_id = node.get_parent_id().ok().flatten();
            new_tree.add_node(Node::new(node_id, None), parent_id.as_ref()).unwrap();
        }
        new_tree
    }
}


fn convert_to_verifier_tree(tree: &ProverAggregationTree<CortadoAffine>) -> VerifierAggregationTree<CortadoAffine> {
    let mut verifier_tree = VerifierAggregationTree::new(Some("verifier_tree"));
    for node in tree.get_nodes().iter() {
        let node_id = node.get_node_id().unwrap();
        let parent_id = node.get_parent_id().ok().flatten();
        let node_data = node.get_value().unwrap().unwrap();
        
        verifier_tree.add_node(
            Node::new(
                node_id,
                Some(VerifierAggregatedNodeData {
                    public_key: node_data.public_key,
                    co_public_key: node_data.co_public_key,
                    marker: node_data.marker,
                }),
            ),
            parent_id.as_ref()
        ).unwrap();
    }
    verifier_tree
}


#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ARTAggregatedProof {
    pub Rδ: AggregatedTreeProof, // Rδ gadget proofs
    pub Rσ: CompactProof<cortado::Fr>, // sigma part of the proof
}

impl CanonicalSerialize for AggregatedTreeProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), SerializationError> {
        let serialized = postcard::to_allocvec(&self.0)
            .map_err(|_| SerializationError::InvalidData)?;
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
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        let tree: Tree<u64, (Option<R1CSProof>, CompressedRistretto)> = postcard::from_bytes(&buf)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        Ok(AggregatedTreeProof(tree))
    }
}


fn Rδ_prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    aggregated_tree: &ProverAggregationTree<CortadoAffine>,
) -> Result<AggregatedTreeProof, R1CSError> {
    let start = Instant::now();

    #[cfg(feature = "multi_thread_prover")]
    {
        let pc_gens = Arc::new(pc_gens.clone());
        let bp_gens = Arc::new(bp_gens.clone());
        let aggregated_proof = Arc::new(Mutex::new(AggregatedTreeProof::from(&aggregated_tree.clone())));
        let mut handles = Vec::new();
        let root_id = aggregated_tree.get_root_node().ok_or(R1CSError::FormatError)?.get_node_id().map_err(|_| R1CSError::FormatError)?;
        let k = aggregated_tree.get_nodes().len() - 1; // number of edges
        
        for node_id in aggregated_tree.traverse(&root_id, TraversalStrategy::PreOrder).map_err(|_| R1CSError::FormatError)? {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node.get_parent_id().map_err(|_| R1CSError::FormatError)?;
            let parent = parent_id.map(|x| aggregated_tree.get_node_by_id(&x).unwrap());
            
            if let Some(parent) = parent {
                let node_data = node.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();
                let parent_data = parent.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();
                let aggregated_proof = aggregated_proof.clone();
                let pc_gens = pc_gens.clone();
                let bp_gens = bp_gens.clone();

                let λ_a_i = node_data.secret_key.into_scalar();
                let b_i = node_data.blinding_factor;
                let λ_a_next = parent_data.secret_key.into_scalar();
                let b_next = parent_data.blinding_factor;
                let Q_a_i = node_data.public_key.clone();
                let Q_ab_i = parent_data.public_key.clone();
                let Q_b_i = node_data.co_public_key.unwrap().clone();
                let level = node.get_children_ids().unwrap().len(); // for leaves level is 0
                handles.push(std::thread::spawn(move || {
                    let mut transcript = Transcript::new(b"ARTGadget");
                    let mut prover = Prover::new(&pc_gens, &mut transcript);
                    let (a_commitment, var_a) = prover.commit(λ_a_i, b_i);
                    let (ab_commitment, var_ab) = prover.commit(λ_a_next, b_next);
                    let λ_a_i = AllocatedScalar::new(var_a, Some(λ_a_i));
                    let λ_a_next = AllocatedScalar::new(var_ab, Some(λ_a_next));
                
                    art_level_gadget(2, &mut prover, level, λ_a_i, λ_a_next, Q_a_i, Q_ab_i, Q_b_i).unwrap();
                
                    let proof = prover.prove(&bp_gens).unwrap();
                    let lock = aggregated_proof.lock().unwrap();
                    let proof_node = lock.0.get_node_by_id(&node_id).unwrap();
                    let proof_parent = lock.0.get_node_by_id(&parent_id.unwrap()).unwrap();
                    if parent_id.unwrap() == root_id {
                        proof_parent.update_value(|x| *x = Some((None, CompressedRistretto(ab_commitment)))).unwrap();
                    }
                    proof_node.update_value(|x| *x = Some((Some(R1CSProof(proof)), CompressedRistretto(a_commitment)))).unwrap();
                }));
            }

            /*node.update_value(|x| if let Some(x) = x.as_mut() {
                x.marker = true;
            }).map_err(|_| R1CSError::FormatError)?;*/
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let proof_len = aggregated_proof.lock().unwrap().serialized_size(Compress::Yes);
        debug!(
            "aggregated Rδ_prove (parallel) for depth {k} proving time: {:?}, proof_len: {proof_len}",
            start.elapsed()
        );
        Ok(
            (*aggregated_proof.lock().unwrap()).clone()
        )
    }
    #[cfg(not(feature = "multi_thread_prover"))]
    {
        let mut aggregated_proof = AggregatedTreeProof::from(aggregated_tree);
        let root_id = aggregated_tree.get_root_node().ok_or(R1CSError::FormatError)?.get_node_id().map_err(|_| R1CSError::FormatError)?;

        let mut transcript = Transcript::new(b"ARTGadget");
        let mut prover = Prover::new(pc_gens, &mut transcript);
        for node_id in aggregated_tree.traverse(&root_id, TraversalStrategy::PreOrder).map_err(|_| R1CSError::FormatError)? {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node.get_parent_id().map_err(|_| R1CSError::FormatError)?;
            
            if let Some(parent_id) = parent_id {
                let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                let node_data = node.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();
                let parent_data = parent.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();

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

                art_level_gadget(2, &mut prover, level, λ_a_i, λ_a_next, Q_a_i, Q_ab_i, Q_b_i)?;

                if parent_id == root_id {
                    aggregated_proof.0.get_node_by_id(&parent_id).unwrap()
                        .update_value(|x| *x = Some((None, CompressedRistretto(ab_commitment)))).unwrap();
                }
                aggregated_proof.0.get_node_by_id(&node_id).unwrap()
                    .update_value(|x| *x = Some((None, CompressedRistretto(a_commitment)))).unwrap();
            }
        }
        let proof = prover.prove(bp_gens)?;
        aggregated_proof.0.get_node_by_id(&root_id).unwrap()
            .update_value(|x| if let Some(x) = x.as_mut() {
                *x = (Some(R1CSProof(proof)), x.1.clone());
            }).unwrap(); // place whole proof in the root node
        let proof_len = aggregated_proof.serialized_size(Compress::Yes);
        debug!(
            "aggregated Rδ_prove (sequential) for depth {} proving time: {:?}, proof_len: {}",
            aggregated_tree.get_nodes().len() - 1,
            start.elapsed(),
            proof_len
        );
        Ok(aggregated_proof)
    }
}

fn Rδ_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
    proof_tree: &AggregatedTreeProof,
) -> Result<(), R1CSError> {
    let start = Instant::now();

    #[cfg(feature = "multi_thread_verifier")]
    {
        let pc_gens = Arc::new(pc_gens.clone());
        let bp_gens = Arc::new(bp_gens.clone());
        let (tx, rx) = mpsc::channel();
        let mut handles = Vec::new();
        let root_id = aggregated_tree.get_root_node().ok_or(R1CSError::FormatError)?.get_node_id().map_err(|_| R1CSError::FormatError)?;
        
        for node_id in aggregated_tree.traverse(&root_id, TraversalStrategy::PreOrder).map_err(|_| R1CSError::FormatError)? {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node.get_parent_id().map_err(|_| R1CSError::FormatError)?;
            
            if let Some(parent_id) = parent_id {
                let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                let node_data = node.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();
                let parent_data = parent.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();

                let proof_node = proof_tree.0.get_node_by_id(&node_id).unwrap();
                let proof_parent = proof_tree.0.get_node_by_id(&parent_id).unwrap();
                let proof_node_data = proof_node.get_value().map_err(|_| R1CSError::FormatError)?;
                let proof_parent_data = proof_parent.get_value().map_err(|_| R1CSError::FormatError)?;

                let tx = tx.clone();
                let pc_gens = pc_gens.clone();
                let bp_gens = bp_gens.clone();
                let Q_a_i = node_data.public_key.clone();
                let Q_b_i = node_data.co_public_key.unwrap().clone();
                let Q_ab_i = parent_data.public_key.clone();
                let (proof, commitment_i) = proof_node_data.ok_or(R1CSError::FormatError)?;
                let proof = proof.ok_or(R1CSError::FormatError)?;
                let (_, commitment_next) = proof_parent_data.ok_or(R1CSError::FormatError)?;
                let level = node.get_children_ids().unwrap().len();

                handles.push(std::thread::spawn(move || {
                    let mut transcript = Transcript::new(b"ARTGadget");
                    let mut verifier = Verifier::new(&mut transcript);
                    let var_a = verifier.commit(commitment_i.0);
                    let var_ab = verifier.commit(commitment_next.0);
                    let λ_a_i = AllocatedScalar::new(var_a, None);
                    let λ_a_next = AllocatedScalar::new(var_ab, None);
                    let _ = tx.send(
                        art_level_gadget(2, &mut verifier, level, λ_a_i, λ_a_next, Q_a_i, Q_ab_i, Q_b_i)
                            .and_then(|_| verifier.verify(&proof.0, &pc_gens, &bp_gens)),
                    );
                }));
            }
        }

        for _ in handles {
            rx.recv().unwrap()?;
        }
    }
    #[cfg(not(feature = "multi_thread_verifier"))]
    {
        let mut transcript = Transcript::new(b"ARTGadget");
        let mut verifier = Verifier::new(&mut transcript);
        let root_id = aggregated_tree.get_root_node().ok_or(R1CSError::FormatError)?.get_node_id().map_err(|_| R1CSError::FormatError)?;
        
        for node_id in aggregated_tree.traverse(&root_id, TraversalStrategy::PreOrder).map_err(|_| R1CSError::FormatError)? {
            let node = aggregated_tree.get_node_by_id(&node_id).unwrap();
            let parent_id = node.get_parent_id().map_err(|_| R1CSError::FormatError)?;
            
            if let Some(parent_id) = parent_id {
                let parent = aggregated_tree.get_node_by_id(&parent_id).unwrap();
                let node_data = node.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();
                let parent_data = parent.get_value().map_err(|_| R1CSError::FormatError)?.unwrap();

                let proof_node = proof_tree.0.get_node_by_id(&node_id).unwrap();
                let proof_parent = proof_tree.0.get_node_by_id(&parent_id).unwrap();
                let proof_node_data = proof_node.get_value().map_err(|_| R1CSError::FormatError)?;
                let proof_parent_data = proof_parent.get_value().map_err(|_| R1CSError::FormatError)?;

                let Q_a_i = node_data.public_key.clone();
                let Q_b_i = node_data.co_public_key.unwrap().clone();
                let Q_ab_i = parent_data.public_key.clone();
                let (_, commitment_i) = proof_node_data.ok_or(R1CSError::FormatError)?;
                let (_, commitment_next) = proof_parent_data.ok_or(R1CSError::FormatError)?;
                let level = node.get_children_ids().unwrap().len();

                let var_a = verifier.commit(commitment_i.0);
                let var_ab = verifier.commit(commitment_next.0);
                let λ_a_i = AllocatedScalar::new(var_a, None);
                let λ_a_next = AllocatedScalar::new(var_ab, None);

                art_level_gadget(2, &mut verifier, level, λ_a_i, λ_a_next, Q_a_i, Q_ab_i, Q_b_i)?;
                
            }
        }
        let proof = proof_tree.0.get_node_by_id(&root_id).unwrap()
            .get_value().map_err(|_| R1CSError::FormatError)?.ok_or(R1CSError::FormatError)?.0.ok_or(R1CSError::FormatError)?;
        verifier.verify(&proof.0, &pc_gens, &bp_gens)?;
    }

    debug!(
        "aggregated Rδ_verify for depth {} verification time: {:?}",
        aggregated_tree.get_nodes().len() - 1,
        start.elapsed()
    );
    Ok(())
}

/// generate an aggregated ART update proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself), additional public keys R,
/// path public keys Q_a, reciprocal co-path public keys Q_b, ART path secrets λ_a, auxiliary 𝔾_1 secrets s, and blinding factors for λ_a
pub fn art_aggregated_prove(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    aggregated_tree: &ProverAggregationTree<CortadoAffine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    s: Vec<cortado::Fr>,   // auxiliary 𝔾_1 secrets
) -> Result<ARTAggregatedProof, R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens {
        B: ark_to_ristretto255(basis.G_2).unwrap(),
        B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
    };
    let bp_gens = BulletproofGens::new(estimate_bp_gens(aggregated_tree.get_nodes().len()-1, 2), 1);

    #[cfg(feature = "cross_sigma")]
    {
        unimplemented!()
    }
    #[cfg(not(feature = "cross_sigma"))]
    {
        let levels_proof = Rδ_prove(
            &pc_gens,
            &bp_gens,
            aggregated_tree,
        )?;

        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        let mut prover: SigmaProver<CortadoAffine, Transcript, &mut Transcript> =
            SigmaProver::new(b"R_sigma", &mut transcript);

        let (var_P, _) = prover.allocate_point(b"P", basis.G_1);
        for (i, s) in s.iter().enumerate() {
            let var_s = prover.allocate_scalar(b"s", *s);
            let (var_R, _) = prover.allocate_point(b"R", R[i]);
            prover.constrain(var_R, vec![(var_s, var_P)]);
        }
        let sigma_proof = prover.prove_compact();

        debug!("ART proof generation time: {:?}", start.elapsed());
        Ok(ARTAggregatedProof {
            Rδ: levels_proof,
            Rσ: sigma_proof,
        })
    }
}

/// verify an ART proof provided basis, auxiliary data ad(typycally a hash of the ART or the ART itself),
/// additional public keys R, user path Q_a, reciprocal co-path public keys Q_b, and the ART proof itself
pub fn art_aggregated_verify(
    basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    ad: &[u8], // auxiliary data
    aggregated_tree: &VerifierAggregationTree<CortadoAffine>,
    R: Vec<CortadoAffine>, // auxiliary public keys
    proof: &ARTAggregatedProof,
) -> Result<(), R1CSError> {
    let start = Instant::now();

    let pc_gens = PedersenGens {
        B: ark_to_ristretto255(basis.G_2).unwrap(),
        B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
    };
    let bp_gens = BulletproofGens::new(estimate_bp_gens(aggregated_tree.get_nodes().len()-1, 2), 1);

    #[cfg(feature = "cross_sigma")]
    {
        unimplemented!()
    }
    #[cfg(not(feature = "cross_sigma"))]
    {
        Rδ_verify(&pc_gens, &bp_gens, aggregated_tree, &proof.Rδ)?;

        let mut transcript = Transcript::new(b"R_sigma");
        transcript.append_message(b"ad", ad);
        let mut verifier: SigmaVerifier<CortadoAffine, Transcript, &mut Transcript> =
            SigmaVerifier::new(b"R_sigma", &mut transcript);

        let var_P = verifier.allocate_point(b"P", basis.G_1)
            .map_err(|_| R1CSError::GadgetError {
                description: "Failed to allocate point P".to_string(),
            })?;

        for (i, R) in R.iter().enumerate() {
            let var_s = verifier.allocate_scalar(b"s");
            let var_R = verifier.allocate_point(b"R", R.clone())
                .map_err(|_| R1CSError::GadgetError {
                    description: "Failed to allocate point R".to_string(),
                })?;
            verifier.constrain(var_R, vec![(var_s, var_P)]);
        }
        verifier.verify_compact(&proof.Rσ)
            .map_err(|e| R1CSError::GadgetError {
                description: format!("Rσ_verify failed: {e:?}"),
            })?;

        debug!("ART proof verification time: {:?}", start.elapsed());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use tracing_subscriber::field::debug;
    use zkp::ProofError;
    use super::*;

    fn get_leaf_nodes<G: AffineRepr>(tree: &ProverAggregationTree<G>) -> Vec<u64> {
        let mut leaf_nodes = Vec::new();
        
        // Get all nodes
        for node in tree.get_nodes().iter() {
            let node_id = node.get_node_id().unwrap();
            // A leaf node has no children
            if node.get_children_ids().unwrap().is_empty() {
                leaf_nodes.push(node_id);
            }
        }

        leaf_nodes
    }

    fn traverse_from_leaves<G: AffineRepr>(
        tree: &ProverAggregationTree<G>,
        mut visitor: impl FnMut(&Node<u64, ProverAggregatedNodeData<G>>) -> Result<(), R1CSError>
    ) -> Result<(), R1CSError> {
        // Get leaf nodes
        let leaf_nodes = get_leaf_nodes(tree);
        let mut visited = std::collections::HashSet::new();

        // Process each path from leaf to root
        for leaf_id in leaf_nodes {
            let mut current_id = leaf_id;

            while let Some(current_node) = tree.get_node_by_id(&current_id) {
                // Only process node if we haven't seen it yet
                if !visited.contains(&current_id) {
                    visitor(&current_node)?;
                    visited.insert(current_id);
                }

                // Move to parent
                if let Ok(Some(parent_id)) = current_node.get_parent_id() {
                    current_id = parent_id;
                } else {
                    break; // Reached root
                }
            }
        }

        Ok(())
    }

    fn generate_random_tree(k: usize) -> ProverAggregationTree<CortadoAffine> {
        let mut rng = &mut thread_rng();
        let mut tree = ProverAggregationTree::new(Some("test_prover_tree"));
        let root_sk = cortado::Fr::rand(&mut rng);
        let root_pk = (CortadoAffine::generator() * root_sk).into_affine();
        let root_node = Node::new(
            0,
            Some(ProverAggregatedNodeData {
                public_key: root_pk,
                co_public_key: None,
                secret_key: root_sk,
                blinding_factor: Scalar::random(&mut rng),
                marker: false,
            }),
        );
        tree.add_node(root_node, None).unwrap();

        let mut node_count = 1;
        let mut available_parents: Vec<u64> = vec![0];
        
        // generation of random quasi-binary tree
        while node_count < k {
            if available_parents.is_empty() {
                break;
            }
            
            // Select random available parent directly from the list
            let parent_id = available_parents[rng.gen_range(0..available_parents.len())];
            let parent_node = tree.get_node_by_id(&parent_id).unwrap();
            
            // Check if parent already has 2 children
            if parent_node.get_children_ids().unwrap().len() >= 2 {
                // Remove this parent from available list since it's full
                available_parents.retain(|&x| x != parent_id);
                continue;
            }
            
            let sk = cortado::Fr::rand(&mut rng);
            let pk = (CortadoAffine::generator() * sk).into_affine();
            // Get sibling pk if exists, otherwise generate random point
            let co_pk = if let Some(sibling_id) = parent_node.get_children_ids().unwrap().first() {
                let sibling = tree.get_node_by_id(sibling_id).unwrap();
                let sibling_data = sibling.get_value().unwrap().unwrap();
                // Update sibling's co_pk with this node's pk
                sibling.update_value(|x| if let Some(x) = x.as_mut() {
                    x.co_public_key = Some(pk);
                }).unwrap();
                sibling_data.public_key
            } else {
                let co_sk = cortado::Fr::rand(&mut rng);
                (CortadoAffine::generator() * co_sk).into_affine()
            };
            
            let node = Node::new(
            node_count as u64,
            Some(ProverAggregatedNodeData {
                public_key: pk,
                co_public_key: Some(co_pk),
                secret_key: sk,
                blinding_factor: Scalar::random(&mut rng),
                marker: false,
            }),
            );
            
            tree.add_node(node, Some(&parent_id)).unwrap();
            available_parents.push(node_count as u64);
            node_count += 1;
        }

        tree
    }

    fn aggregated_art_roundtrip(k: usize) {
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
        debug!("Prover tree: {prover_tree}");

        // Generate auxiliary values
        let s = (0..2)
            .map(|_| cortado::Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let R = s
            .iter()
            .map(|&x| (G_1 * x).into_affine())
            .collect::<Vec<_>>();

        // Create proof
        let proof = art_aggregated_prove(
            basis.clone(),
            &ad,
            &prover_tree,
            R.clone(),
            s.clone(),
        ).expect("Proof generation should not fail");

        // Get verifier tree from prover tree (only for test, for real use case should use VerifierAggregationTree::from(&proof.Rδ)) and populating the tree from the current ART state
        let verifier_tree = convert_to_verifier_tree(&prover_tree);
        
        // Verify proof
        art_aggregated_verify(
            basis,
            &ad,
            &verifier_tree,
            R,
            &proof,
        ).unwrap();
    }

    #[test]
    fn test_aggregated_art_small() {
        let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

        let _ = tracing_subscriber::fmt()
            .with_env_filter(log_level)
            .with_target(false)
            .try_init();
        aggregated_art_roundtrip(2);
    }

    #[test]
    fn test_aggregated_art_medium() {
        aggregated_art_roundtrip(16);
    }
}