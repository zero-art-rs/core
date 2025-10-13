use crate::types::PublicART;
use crate::{
    helper_tools::{ark_de, ark_se},
    types::NodeIndex,
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
    /// Public part of the art
    pub public_art: PublicART<G>,

    /// Secret key of the leaf in the art. Used to compute toot secret key.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub secret_key: G::ScalarField,

    /// Index of a leaf, corresponding to the `secret_key`.
    pub node_index: NodeIndex,

    /// Set of secret keys on path from leaf (corresponding to the `secret_key`) to root.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path_secrets: Vec<G::ScalarField>,
}
