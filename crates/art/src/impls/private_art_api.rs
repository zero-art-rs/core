// Asynchronous Ratchet Tree implementation

use crate::helper_tools::{iota_function, to_ark_scalar, to_dalek_scalar};
use crate::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, BranchChangesType, ProverArtefacts},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use serde::Serialize;
use serde::de::DeserializeOwned;

impl<G, A> ARTPrivateAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPrivateView<G>,
{
    fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        self.recompute_root_key_using_secret_key(self.get_secret_key(), self.get_node_index())
    }

    fn recompute_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError> {
        // self.recompute_root_key_with_artefacts_using_secret_key(
        //     self.get_secret_key(),
        //     Some(self.get_node_index()),
        // )

        self.recompute_root_key_with_artefacts_using_path_secrets(
            self.get_node_index(),
            self.get_path_secrets().clone(),
        )
    }

    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        self.set_secret_key(new_secret_key);

        let (tk, changers, artefacts) =
            self.update_art_with_secret_key(new_secret_key, &self.get_node_index().get_path()?)?;
        self.update_node_index()?;
        self.set_path_secrets(artefacts.secrets.clone());

        Ok((tk, changers, artefacts))
    }

    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let (tk, changes, artefacts) =
            self.make_blank_public_art(public_key, temporary_secret_key)?;
        self.update_path_secrets_with(&artefacts.secrets, &changes.node_index)?;

        Ok((tk, changes, artefacts))
    }

    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let (tk, changes, artefacts) = self.append_node_public_art(secret_key)?;
        self.update_path_secrets_with(&artefacts.secrets, &changes.node_index)?;

        Ok((tk, changes, artefacts))
    }

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        self.update_public_art(changes)?;

        match &changes.change_type {
            BranchChangesType::AppendNode => self.update_node_index()?,
            _ => {}
        };

        let (_, artefacts) = self
            .recompute_root_key_with_artefacts_using_secret_key(
                self.get_secret_key(),
                self.get_node_index(),
            )?;
        self.set_path_secrets(artefacts.secrets);

        Ok(())
    }

    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError> {
        let old_secrets = self.get_path_secrets().clone();

        self.recompute_path_secrets_for_participant(target_changes, &self.clone())?;

        // subtract default secrets from path_secrets
        let path_secrets = self.get_mut_path_secrets();
        for i in (0..old_secrets.len()).rev() {
            if path_secrets[i] != old_secrets[i] {
                // path_secrets[i] -= old_secrets[i];
                path_secrets[i] = to_dalek_scalar::<G>(
                    to_ark_scalar::<G>(path_secrets[i]) - to_ark_scalar::<G>(old_secrets[i]),
                )?;
            } else {
                return Ok(());
            }
        }

        Ok(())
    }

    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &Vec<BranchChanges<G>>,
        base_fork: &A,
    ) -> Result<(), ARTError> {
        for change in target_changes {
            let mut fork = base_fork.clone();
            fork.update_private_art(change)?;

            let co_path_values = fork.get_co_path_values(fork.get_node_index())?;
            let mut secrets = Vec::with_capacity(co_path_values.len() + 1);
            secrets.push(Scalar::from_bytes_mod_order(
                fork.get_secret_key()
                    .into_bigint()
                    .to_bytes_le()
                    .try_into()
                    .unwrap(),
            ));
            let mut ark_secret = fork.get_secret_key();
            for public_key in co_path_values.iter() {
                let secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
                secrets.push(secret);
                ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
            }

            self.merge_path_secrets(&secrets, &change.node_index)?;
        }

        Ok(())
    }
}
