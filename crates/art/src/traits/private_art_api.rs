use crate::{
    errors::ARTError,
    traits::ARTPublicAPI,
    types::{ARTRootKey, BranchChanges, Artefacts},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait ARTPrivateAPI<G>: ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key_with_artefacts(&self) -> Result<(ARTRootKey<G>, Artefacts<G>), ARTError>;

    /// Changes old_secret_key secret key of a leaf to the new_secret_key.
    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;
}
