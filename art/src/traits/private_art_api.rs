use crate::types::Direction;
use crate::{
    errors::ARTError,
    traits::ARTPublicAPI,
    types::{ARTRootKey, BranchChanges, ProverArtefacts},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;

pub trait ARTPrivateAPI<G>: ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Returns actual root key, stored at the end of path_secrets.
    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Changes old_secret_key of a user leaf to the new_secret_key and update path_secrets.
    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Converts a leaf node, which is on the given path, to blank one and update path_secrets
    fn make_blank(
        &mut self,
        path: &Vec<Direction>,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Append new node to the tree or replace the blank one. It also updates `path_secrets`.
    fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

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
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError>;

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if user
    /// had made change for merge. The state of the ART without that change is the base_fork,
    /// which is required to properly merge changes. Note, that `target_changes` doesnt contain
    /// users update, because it merges all path_secrets to the self path_secrets.
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
        base_fork: &Self,
    ) -> Result<(), ARTError>;
}
