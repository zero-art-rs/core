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
        /// If `initiation` is true, then the change was done for unblanked user. Else it is a
        /// participation in the user removal, and it should be merged
        blank_pk: G,
    },
    AppendNode {
        /// If true, marks that the targeted node was blank. Else it wasn't.
        extend: bool,
    },
    UpdateKey {
        pk: G,
    },
    /// Means, that the node can't be computed by usual means. This doesn't provide a branch
    /// change, but it works as a marker for key_update and make blank branch changes extractor.
    AppendNodeFix,
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
