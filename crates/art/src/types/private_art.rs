use crate::traits::ARTPublicView;
use crate::types::BranchChanges;
use crate::{
    errors::ARTError,
    helper_tools::{ark_de, ark_se},
    traits::ARTPublicAPI,
    types::{ARTNode, ARTRootKey, NodeIndex, PublicART},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
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
    pub merged_changes: Vec<BranchChanges<G>>,
}
