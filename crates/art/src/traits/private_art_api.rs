use crate::{
    errors::ARTError,
    traits::ARTPublicAPI,
    types::{ARTRootKey, BranchChanges, ProverArtefacts},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use crate::types::Direction;

pub trait ARTPrivateAPI<G>: ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Recomputes art root key using the given leaf secret key. It might not work if there was
    /// merge operation recently.
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Returns actual root key, stored at the end of path_secrets.
    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Recomputes art root key and prover artefacts using secret keys stored in the path_secrets.
    fn get_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

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

    /// Append new node to the tree or replace the blank one, and update path_secrets.
    fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if the user
    /// didn't make any changes, which where merged.
    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError>;

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if user
    /// had made change for merge. The state of the ART without that change is the base_fork,
    /// which is required to properly merge changes
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
        base_fork: &Self,
    ) -> Result<(), ARTError>;
}
