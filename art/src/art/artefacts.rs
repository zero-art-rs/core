use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::error;
use zrt_zk::art::{ProverNodeData, VerifierNodeData};

/// Additional data, which can be used for proof creation.
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Default)]
pub struct ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    /// Public keys of nodes on path from root to leaf.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,

    /// Public keys of sibling nodes on path from root to leaf. There is exactly one less key
    /// in the `co_path`.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,

    /// Secret keys of nodes on path form root to leaf.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub secrets: Vec<G::ScalarField>,
}

/// Additional data, which can be used for proof verification.
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Default)]
pub struct VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    /// Public keys of nodes on path from root to leaf.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,

    /// Public keys of sibling nodes on path from root to leaf. There is exactly one less key
    /// in the `co_path`.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,
}

impl<G> ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new(path: Vec<G>, co_path: Vec<G>, secrets: Vec<G::ScalarField>) -> Self {
        Self {
            path,
            co_path,
            secrets,
        }
    }

    pub fn to_prover_branch<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<ProverNodeData<G>>, ArtError> {
        if self.path.len() != self.secrets.len() || self.path.len() != self.co_path.len() + 1 {
            return Err(ArtError::InvalidInput);
        }

        let mut prover_nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            prover_nodes.push(ProverNodeData::<G> {
                secret_key: *self.secrets.get(i).ok_or(ArtError::InvalidInput)?,
                blinding_factor: G::ScalarField::rand(rng),
                public_key: *self.path.get(i).ok_or(ArtError::InvalidInput)?,
                co_public_key: self.co_path.get(i).copied(),
            })
        }

        Ok(prover_nodes)
    }

    pub fn derive_branch_change(
        &self,
        change_type: BranchChangeType,
        node_index: NodeIndex,
    ) -> Result<BranchChange<G>, ArtError> {
        Ok(BranchChange {
            change_type,
            public_keys: self.path.iter().rev().cloned().collect(),
            node_index: node_index.as_index()?,
        })
    }
}

impl<G> VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new(path: Vec<G>, co_path: Vec<G>) -> Self {
        Self { path, co_path }
    }

    pub fn to_verifier_branch(&self) -> Result<Vec<VerifierNodeData<G>>, ArtError> {
        if self.path.len() != self.co_path.len() + 1 {
            error!(
                "Fail to convert to verifier branch as path length is {}, while co path length is {}",
                self.path.len(),
                self.co_path.len()
            );
            return Err(ArtError::InvalidInput);
        }

        let mut nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            nodes.push(VerifierNodeData::<G> {
                public_key: *self.path.get(i).ok_or(ArtError::PathNotExists)?,
                co_public_key: self.co_path.get(i).copied(),
            })
        }

        Ok(nodes)
    }
}
