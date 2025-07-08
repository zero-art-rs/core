// Asynchronous Ratchet Tree implementation

use crate::{ARTError, ARTPrivateAPI};
use crate::{ARTPrivateView, ARTPublicAPI, ARTRootKey, BranchChanges};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use serde::Serialize;
use serde::de::DeserializeOwned;

impl<G, PrivateART> ARTPrivateAPI<G> for PrivateART
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    PrivateART: ARTPrivateView<G>,
{
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        <Self as ARTPublicAPI<G>>::recompute_root_key_public(self, self.get_secret_key())
    }

    fn recompute_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError> {
        <Self as ARTPublicAPI<G>>::recompute_root_key_with_artefacts_public(
            self,
            self.get_secret_key(),
        )
    }

    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let old_key = self.get_secret_key();
        self.set_secret_key(new_secret_key);

        <Self as ARTPublicAPI<G>>::update_key_public(self, &old_key, new_secret_key)
    }
}
