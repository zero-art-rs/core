use crate::{ARTNode, Direction, ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use postcard::{from_bytes, to_allocvec};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum BranchChangesType<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    MakeTemporal(
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G::ScalarField,
    ),
    AppendNode(ARTNode<G>),
    UpdateKeys,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    RemoveNode(G),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct BranchChanges<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub change_type: BranchChangesType<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_keys: Vec<G>,
    pub next: Vec<Direction>,
}

impl<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> BranchChanges<G> {
    pub fn serialize(&self) -> postcard::Result<Vec<u8>> {
        to_allocvec(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> postcard::Result<Self> {
        from_bytes(bytes)
    }
}
