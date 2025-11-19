//! Module with branch changes of the ART.

// use crate::art::{
//     PrivateArt, PublicArt, handle_potential_art_node_extension_on_add_member,
//     handle_potential_marker_tree_node_extension_on_add_member, update_secrets_if_need,
// };
// use crate::changes::aggregations::AggregationNode;
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, rc::Rc};
use zrt_zk::{EligibilityArtefact, art::ProverNodeData, engine::ZeroArtProverEngine};

/// Marker for a `BranchChange` type.
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
#[derive(Debug, Clone, Deserialize, Serialize, Default, Eq, PartialEq)]
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

/// Helper data type, which along with the `branch_change` contain additional
/// artefacts, which can be used to create a proof.
#[derive(Clone)]
pub struct PrivateBranchChange<G>
where
    G: AffineRepr,
{
    pub(crate) branch_change: BranchChange<G>,
    pub(crate) prover_branch: Vec<ProverNodeData<G>>,
    pub(crate) eligibility: EligibilityArtefact,
    pub(crate) leaf_secret: G::ScalarField,
    pub(crate) root_secret: G::ScalarField,
    pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
}

impl<G> PrivateBranchChange<G>
where
    G: AffineRepr,
{
    pub fn get_root_secret(&self) -> G::ScalarField {
        self.root_secret
    }

    pub fn get_branch_change(&self) -> &BranchChange<G> {
        &self.branch_change
    }

    pub fn get_eligibility(&self) -> &EligibilityArtefact {
        &self.eligibility
    }

    pub fn get_secret(&self) -> G::ScalarField {
        self.leaf_secret
    }

    pub fn get_prover_branch(&self) -> &Vec<ProverNodeData<G>> {
        &self.prover_branch
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

/// Marker for a `BranchChange` type. Similar to `BranchChangesType`, but with
/// additional public data.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum BranchChangeTypeHint<G>
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

impl<G> From<&BranchChangeTypeHint<G>> for BranchChangeType
where
    G: AffineRepr,
{
    fn from(value: &BranchChangeTypeHint<G>) -> Self {
        match value {
            BranchChangeTypeHint::RemoveMember { .. } => BranchChangeType::RemoveMember,
            BranchChangeTypeHint::AddMember { .. } => BranchChangeType::AddMember,
            BranchChangeTypeHint::UpdateKey { .. } => BranchChangeType::UpdateKey,
            BranchChangeTypeHint::Leave { .. } => BranchChangeType::Leave,
        }
    }
}
