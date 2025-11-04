//! Module with branch changes of the ART.

use crate::art::ProverArtefacts;
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::rc::Rc;
use curve25519_dalek::digest::generic_array::sequence::Concat;
use cortado::CortadoAffine;
use zrt_zk::art::ProverNodeData;
use zrt_zk::EligibilityArtefact;
use zrt_zk::engine::ZeroArtProverEngine;

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

    /// Index of the target leaf
    pub node_index: NodeIndex,
}

/// Helper data structure, which along with the `branch_change` of a the contain additional
/// artefacts, which can be used to create a proof.
#[derive(Clone)]
pub struct PrivateBranchChange<G>
where
    G: AffineRepr,
{
    pub(crate) branch_change: BranchChange<G>,
    pub(crate) prover_branch: Vec<ProverNodeData<G>>,
    pub(crate) eligibility: EligibilityArtefact,
    pub(crate) secret: G::ScalarField,
    pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
}

impl<G> PrivateBranchChange<G>
where
    G: AffineRepr,
{
    pub fn new(
        branch_change: BranchChange<G>,
        prover_branch: Vec<ProverNodeData<G>>,
        eligibility: EligibilityArtefact,
        secret: G::ScalarField,
        prover_engine: Rc<ZeroArtProverEngine>,
    ) -> Result<Self, ArtError> {
        Ok(Self {
            branch_change,
            prover_branch,
            eligibility,
            secret,
            prover_engine,
        })
    }

    pub fn get_branch_change(&self) -> &BranchChange<G> {
        &self.branch_change
    }

    pub fn get_eligibility(&self) -> &EligibilityArtefact {
        &self.eligibility
    }
}

impl<G> From<PrivateBranchChange<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn from(output: PrivateBranchChange<G>) -> Self {
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
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pk: G,

        /// If true, that blanking is the commit blanking, else it is initialisation.
        merge: bool,
    },
    AddMember {
        /// If `Some<new_pk>`, then the node was extended and the `new_pk` is the new public key
        /// of the node, else the node was replaced.
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        ext_pk: Option<G>,

        /// New user public key.
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pk: G,
    },
    UpdateKey {
        /// New public key
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pk: G,
    },
    Leave {
        /// New public key
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
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

/// Helper data structure, which can combine several changes from different
/// users into one merge change.
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
