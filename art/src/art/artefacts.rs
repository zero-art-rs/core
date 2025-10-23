use crate::errors::ARTError;
use crate::helper_tools::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::SeekFrom::Start;
use zrt_zk::art::{ProverBranchNode, VerifierBranchNode};

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
    ) -> Result<Vec<ProverBranchNode<G>>, ARTError> {
        if self.path.len() != self.secrets.len() || self.path.len() != self.co_path.len() + 1 {
            return Err(ARTError::InvalidInput);
        }

        let mut prover_nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            prover_nodes.push(ProverBranchNode::<G> {
                secret: *self.secrets.get(i).ok_or(ARTError::InvalidInput)?,
                blinding_factor: G::ScalarField::rand(rng),
                public_key: *self.path.get(i).ok_or(ARTError::InvalidInput)?,
                co_public_key: self.co_path.get(i).map(|g| *g),
            })
        }

        Ok(prover_nodes)
    }
}

impl<G> VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn new(path: Vec<G>, co_path: Vec<G>) -> Self {
        Self { path, co_path }
    }

    pub fn to_verifier_branch(&self) -> Result<Vec<VerifierBranchNode<G>>, ARTError> {
        if self.path.len() != self.co_path.len() + 1 {
            return Err(ARTError::InvalidInput);
        }

        let mut nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            nodes.push(VerifierBranchNode::<G> {
                public_key: *self.path.get(i).ok_or(ARTError::InvalidInput)?,
                co_public_key: self.co_path.get(i).map(|g| *g),
            })
        }

        Ok(nodes)
    }
}
