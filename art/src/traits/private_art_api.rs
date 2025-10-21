use crate::helper_tools::recompute_artefacts;
use crate::traits::ChildContainer;
use crate::{
    errors::ARTError,
    traits::ARTPublicAPI,
    types::{
        ARTRootKey, BranchChanges, ChangeAggregationNode, Direction, NodeIndex,
        ProverAggregationData, ProverArtefacts, UpdateData, VerifierAggregationData,
    },
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Trait which contains methods to work with abstract Private ART tree.
///
/// It extends `ARTPublicAPI`. The difference from `ARTPublicAPI` is that the trait is designed
/// to work with stored leaf secret key.
pub trait ARTPrivateAPI<G>: ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Returns actual root key, stored at the end of path_secrets.
    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Changes old_secret_key of a user leaf to the new_secret_key and update path_secrets.
    fn update_key(&mut self, new_secret_key: &G::ScalarField) -> Result<UpdateData<G>, ARTError>;

    /// Converts a leaf node, which is on the given path, to blank one and update path_secrets
    fn make_blank(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<UpdateData<G>, ARTError>;

    /// Append new node to the tree or replace the blank one. It also updates `path_secrets`.
    fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<UpdateData<G>, ARTError>;

    /// Remove yourself from the art.
    fn leave(&mut self, new_secret_key: G::ScalarField) -> Result<UpdateData<G>, ARTError>;

    /// Updates art by applying changes. Also updates `path_secrets` and `node_index`.
    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Update ART with `target_changes` for the user, which didnt participated it the
    /// merge conflict.
    fn merge_for_observer(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError>;

    /// Update ART with `target_changes`, if the user contributed to the merge conflict with his
    /// `applied_change`. Requires `base_fork`, which is the previous state of the ART, with
    /// unapplied user provided `applied_change`. Currently, it will fail if the first applied
    /// change is append_member.
    fn merge_for_participant(
        &mut self,
        applied_change: BranchChanges<G>,
        target_changes: &[BranchChanges<G>],
        base_fork: Self,
    ) -> Result<(), ARTError>;
}

pub(crate) trait ARTPrivateAPIHelper<G>: ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    /// Updates users node index by researching it in a tree.
    fn update_node_index(&mut self) -> Result<(), ARTError>;

    /// If `append_changes` is false, works as `set_path_secrets`. In the other case, it will
    /// append secrets to available ones. Works correctly if `self.node_index` isn't a subpath
    /// of the `other`. The `other` is used to properly decide, which secrets did change.
    fn update_path_secrets(
        &mut self,
        other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ARTError>;

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    fn update_private_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError>;

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if the user
    /// didn't make any changes, which where merged. It is a wrapper for
    /// `recompute_path_secrets_for_participant`. The difference, is then for observer we cant
    /// merge all secrets, we need to apply one and then append others.
    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError>;

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if user
    /// had made change for merge. The state of the ART without that change is the base_fork,
    /// which is required to properly merge changes. Note, that `target_changes` doesn't contain
    /// users update, because it merges all path_secrets to the self path_secrets.
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &[BranchChanges<G>],
        base_fork: Self,
    ) -> Result<(), ARTError>;

    /// Returns secrets from changes (ordering from leaf to the root).
    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChanges<G>,
    ) -> Result<Vec<G::ScalarField>, ARTError>;

    /// Instead of recomputing path secretes from the leaf to root, this method takes some secret
    /// key in `path_secrets`, considering previous are unchanged, and recomputes the remaining
    /// `path_secrets`, which have changed. `partial_co_path` is a co-path from some inner node to
    /// the root, required to compute secrets.
    fn get_partial_path_secrets(
        &self,
        partial_co_path: &[G],
    ) -> Result<Vec<G::ScalarField>, ARTError>;
}
