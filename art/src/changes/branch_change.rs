use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zrt_zk::EligibilityArtefact;
use crate::art::ProverArtefacts;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangeType {
    #[default]
    UpdateKey,
    AddMember,
    RemoveMember,
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

#[derive(Debug, Clone)]
pub struct ArtOperationOutput<G>
where
    G: AffineRepr,
{
    pub(crate) branch_change: BranchChange<G>,
    pub(crate) artefacts: ProverArtefacts<G>,
    pub(crate) eligibility: EligibilityArtefact,
}

impl<G> ArtOperationOutput<G>
where 
    G: AffineRepr,
{
    pub fn new(
        branch_change: BranchChange<G>,
        artefacts: ProverArtefacts<G>,
        eligibility: EligibilityArtefact,
    ) -> Self {
        Self {
            branch_change,
            artefacts,
            eligibility,
        }
    }
}

impl<G> From<ArtOperationOutput<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn from(output: ArtOperationOutput<G>) -> Self {
        output.branch_change
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangesTypeHint<G>
where
    G: AffineRepr,
{
    RemoveMember {
        /// Public key used for blanking.
        pk: G,

        /// If true, that blanking is the commit blanking, else it is initialisation.
        merge: bool,
    },
    AddMember {
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

impl<G> From<&BranchChangesTypeHint<G>> for BranchChangeType
where
    G: AffineRepr,
{
    fn from(value: &BranchChangesTypeHint<G>) -> Self {
        match value {
            BranchChangesTypeHint::RemoveMember { .. } => BranchChangeType::RemoveMember,
            BranchChangesTypeHint::AddMember { .. } => BranchChangeType::AddMember,
            BranchChangesTypeHint::UpdateKey { .. } => BranchChangeType::UpdateKey,
            BranchChangesTypeHint::Leave { .. } => BranchChangeType::Leave,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MergeBranchChange<T, C> {
    pub(crate) applied_helper_data: Option<(T, C)>,
    pub(crate) unapplied_changes: Vec<C>,
}

impl<T, C> MergeBranchChange<T, C> {
    pub fn new(
        base_fork: Option<T>,
        applied_change: Option<C>,
        unapplied_changes: Vec<C>,
    ) -> Result<Self, ArtError> {
        Ok(match (base_fork, applied_change) {
            (Some(base_fork), Some(applied_change)) => {
                Self::new_for_participant(base_fork, applied_change, unapplied_changes)
            }
            (None, None) => Self::new_for_observer(unapplied_changes),
            _ => return Err(ArtError::InvalidMergeInput),
        })
    }

    pub fn new_for_observer(unapplied_changes: Vec<C>) -> Self {
        MergeBranchChange {
            applied_helper_data: None,
            unapplied_changes,
        }
    }

    pub fn new_for_participant(base_fork: T, applied_change: C, unapplied_changes: Vec<C>) -> Self {
        MergeBranchChange {
            applied_helper_data: Some((base_fork, applied_change)),
            unapplied_changes,
        }
    }
}
