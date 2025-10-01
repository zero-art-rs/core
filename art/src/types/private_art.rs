use crate::{
    helper_tools::{ark_de, ark_se},
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub secret_key: G::ScalarField,
    pub node_index: NodeIndex,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path_secrets: Vec<G::ScalarField>,
}
