use crate::helper_tools::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
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

#[derive(Deserialize, Serialize, Debug, Clone)]
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
