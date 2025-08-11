use crate::traits::ARTPublicAPI;
use crate::{
    errors::ARTError,
    helper_tools::{ark_de, ark_se},
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum BranchChangesType {
    MakeBlank,
    AppendNode,
    UpdateKey,
    RemoveNode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub change_type: BranchChangesType,
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
