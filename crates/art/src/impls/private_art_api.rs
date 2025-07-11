// Asynchronous Ratchet Tree implementation

use crate::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, BranchChangesType},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use serde::Serialize;
use serde::de::DeserializeOwned;

impl<G, PrtART> ARTPrivateAPI<G> for PrtART
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    PrtART: ARTPrivateView<G>,
{
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        self.recompute_root_key_using_secret_key(self.get_secret_key(), Some(self.get_node_index()))
    }

    fn recompute_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError> {
        self.recompute_root_key_with_artefacts_using_secret_key(
            self.get_secret_key(),
            Some(self.get_node_index()),
        )
    }

    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let old_key = self.get_secret_key();
        self.set_secret_key(new_secret_key);

        let result = self.update_key_with_secret_key(&old_key, new_secret_key);
        self.update_node_index()?;

        result
    }

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        let result = <Self as ARTPublicAPI<G>>::update_public_art(self, changes);

        match &changes.change_type {
            BranchChangesType::AppendNode(_) => {
                self.update_node_index()?;
            }
            _ => {}
        };

        result
    }
}
