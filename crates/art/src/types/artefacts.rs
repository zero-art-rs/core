use crate::helper_tools::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,
    pub secrets: Vec<curve25519_dalek::Scalar>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,
}
