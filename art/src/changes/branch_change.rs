//! Module with branch changes of the ART.

use crate::art::PrivateZeroArt;
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se, recompute_artefacts};
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::rc::Rc;
use zrt_zk::EligibilityArtefact;
use zrt_zk::art::ProverNodeData;
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

    pub fn get_secret(&self) -> G::ScalarField {
        self.secret
    }

    pub fn get_prover_branch(&self) -> &Vec<ProverNodeData<G>> {
        &self.prover_branch
    }

    pub(crate) fn inner_apply_own_key_update<R>(
        &self,
        art: &mut PrivateZeroArt<G, R>,
        new_secret_key: G::ScalarField,
    ) -> Result<(), ArtError>
    where
        R: Rng + ?Sized,
        G: AffineRepr,
        G::BaseField: PrimeField,
    {
        let path = art.get_node_index().get_path()?;
        let co_path = art.base_art.get_public_art().get_co_path_values(&path)?;
        let artefacts = recompute_artefacts(new_secret_key, &co_path)?;

        // get updates secrets length
        let mut parent = &art.marker_tree;
        let mut updated_secrets_length = parent.data as usize;
        if parent.data {
            for dir in &path {
                parent = parent.get_child(*dir).ok_or(ArtError::PathNotExists)?;
                if parent.data {
                    updated_secrets_length += 1;
                }
            }
        }

        let marker_tree = &mut art.marker_tree;
        art.upstream_art.public_art.merge_by_marker(
            &artefacts.path.iter().rev().cloned().collect::<Vec<_>>(),
            &path,
            marker_tree,
        )?;

        let old_secrets = art.upstream_art.secrets.clone();
        art.upstream_art.secrets = artefacts.secrets;

        let start = old_secrets.len() - updated_secrets_length;
        let finish = old_secrets.len();
        art.update_secrets(&old_secrets[start..finish], true)?;

        Ok(())
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
