use crate::{
    errors::ARTError,
    helper_tools::{ark_de, ark_se},
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum BranchChangesType<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    MakeBlank(
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G::ScalarField,
    ),
    AppendNode(ARTNode<G>),
    UpdateKey,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    RemoveNode(G),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct BranchChanges<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub change_type: BranchChangesType<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_keys: Vec<G>,
    pub node_index: NodeIndex,
}

impl<G> BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn serialze(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(self).map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(ARTError::Postcard)
    }
}
