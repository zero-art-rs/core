use crate::{
    helper_tools::{ark_de, ark_se},
    types::NodeIndex,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangesType {
    MakeBlank,
    AppendNode,
    UpdateKey,
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
