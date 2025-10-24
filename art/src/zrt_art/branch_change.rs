use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::CortadoAffine;
use serde::{Deserialize, Serialize};
use zrt_zk::art::ARTProof;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangeType {
    #[default]
    UpdateKey,
    AddMember,
    MakeBlank,
    Leave,
}

/// Helper data type, which contains information about ART change. Can be used to apply this
/// change to the different ART.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(bound = "")]
pub struct BranchChange<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    /// Marker of the change operation.
    pub change_type: BranchChangeType,

    /// Set of updated public keys on the path from the root to the target leaf.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_keys: Vec<G>,

    /// index of the target leaf
    pub node_index: NodeIndex,
}

#[derive(Clone)]
pub struct VerifiableBranchChange {
    pub branch_change: BranchChange<CortadoAffine>,
    pub proof: ARTProof,
}
