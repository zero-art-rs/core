use crate::errors::ARTError;
use crate::{
    helper_tools::{ark_de, ark_se},
    types::NodeIndex,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangesType {
    MakeBlank,
    AppendNode,
    #[default]
    UpdateKey,
    Leave,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangesTypeHint<G>
where
    G: AffineRepr,
{
    MakeBlank {
        /// Public key used for blanking.
        pk: G,

        /// If true, that blanking is the commit blanking, else it is initialisation.
        merge: bool,
    },
    AppendNode {
        /// If `Some<new_pk>`, then the node was extended and the `new_pk` is the new public key
        /// of the node, else the node was replaced.
        ext_pk: Option<G>,

        /// New user public key.
        pk: G,
    },
    UpdateKey {
        /// New public key
        pk: G,
    },
    Leave {
        /// New public key
        pk: G,
    },
}

impl<G> From<&BranchChangesTypeHint<G>> for BranchChangesType
where
    G: AffineRepr,
{
    fn from(value: &BranchChangesTypeHint<G>) -> Self {
        match value {
            BranchChangesTypeHint::MakeBlank { .. } => BranchChangesType::MakeBlank,
            BranchChangesTypeHint::AppendNode { .. } => BranchChangesType::AppendNode,
            BranchChangesTypeHint::UpdateKey { .. } => BranchChangesType::UpdateKey,
            BranchChangesTypeHint::Leave { .. } => BranchChangesType::Leave,
        }
    }
}

/// Helper data type, which contains information about ART change. Can be used to apply this
/// change to the different ART.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(bound = "")]
pub struct BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    /// Marker of the change operation.
    pub change_type: BranchChangesType,

    /// Set of updated public keys on the path from the root to the target leaf.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_keys: Vec<G>,

    /// index of the target leaf
    pub node_index: NodeIndex,
}

impl<G> BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(self).map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(ARTError::Postcard)
    }
}
