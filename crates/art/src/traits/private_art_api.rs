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
    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

    /// Changes old_secret_key secret key of a leaf to the new_secret_key and update path_secrets.
    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Converts a leaf with the given path to blank one and update path_secrets
    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Appends new node to the tree, and update path_secrets.
    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError>;

    /// Updates art by applying changes and update path_secrets and node_index.
    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Recomputes path_secrets from merge of conflict changes. Applicable if the used didn't
    /// make any changes for merge.
    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError>;

    /// Recomputes path_secrets from merge of conflict changes. Applicable if user made some change
    /// for merge.
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
        base_fork: &Self,
    ) -> Result<(), ARTError>;
}
