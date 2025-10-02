// Asynchronous Ratchet Tree implementation

use crate::helper_tools::iota_function;
use crate::traits::ARTPrivateAPIHelper;
use crate::types::{Direction, NodeIndex};
use crate::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, BranchChangesType, ProverArtefacts},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::debug;

impl<G, A> ARTPrivateAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPrivateView<G> + ARTPrivateAPIHelper<G>,
{
    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        Ok(ARTRootKey {
            key: *self.get_path_secrets().last().ok_or(ARTError::EmptyART)?,
            generator: self.get_generator(),
        })
    }

    fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        self.set_secret_key(new_secret_key);

        let (tk, changers, artefacts) = self.update_art_branch_with_leaf_secret_key(
            new_secret_key,
            &self.get_node_index().get_path()?,
            false,
        )?;

        self.set_path_secrets(artefacts.secrets.clone());
        self.update_node_index()?;

        Ok((tk, changers, artefacts))
    }

    fn make_blank(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let append_changes = self.get_node(&NodeIndex::from(path.to_vec()))?.is_blank;
        let (mut tk, changes, artefacts) =
            self.make_blank_in_public_art(path, temporary_secret_key)?;

        if append_changes {
            tk.key += *self.get_path_secrets().last().ok_or(ARTError::EmptyART)?;
        }

        self.update_path_secrets(
            artefacts.secrets.clone(),
            &changes.node_index,
            append_changes,
        )?;

        Ok((tk, changes, artefacts))
    }

    fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        if self.get_path_secrets().is_empty() {
            return Err(ARTError::EmptyART);
        }

        let (tk, changes, artefacts) = self.append_or_replace_node_in_public_art(secret_key)?;
        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            // Extend path_secrets. Append additional leaf secret to the start.
            let mut new_path_secrets =
                vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
            new_path_secrets.append(self.get_path_secrets().clone().as_mut());
            self.set_path_secrets(new_path_secrets);
        }
        self.update_node_index()?;

        self.update_path_secrets(artefacts.secrets.clone(), &changes.node_index, false)?;

        Ok((tk, changes, artefacts))
    }

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && self.get_node(&changes.node_index)?.is_blank
        {
            self.update_private_art_with_options(changes, true, false)
        } else {
            self.update_private_art_with_options(changes, false, true)
        }
    }

    fn merge_for_observer(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError> {
        self.recompute_path_secrets_for_observer(&target_changes)?;
        self.merge(&target_changes)?;

        Ok(())
    }

    fn merge_for_participant(
        &mut self,
        applied_change: BranchChanges<G>,
        unapplied_changes: &[BranchChanges<G>],
        base_fork: Self,
    ) -> Result<(), ARTError> {
        self.recompute_path_secrets_for_participant(&unapplied_changes, base_fork)?;
        self.merge_with_skip(&vec![applied_change], &unapplied_changes)?;

        Ok(())
    }
}

impl<G, A> ARTPrivateAPIHelper<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPrivateView<G>,
{
    fn update_private_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        // If your node is to be blanked, return error, as it is impossible to update
        // path secrets at that point.
        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            match changes.change_type {
                BranchChangesType::MakeBlank => return Err(ARTError::InapplicableBlanking),
                BranchChangesType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                BranchChangesType::AppendNode => {
                    // Extend path_secrets. Append additional leaf secret to the start.
                    let mut new_path_secrets =
                        vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                    new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                    self.set_path_secrets(new_path_secrets);
                }
            }
        }

        // create a fork of the art, to correctly append change
        let mut fork = self.clone();

        self.update_public_art_with_options(changes, append_changes, update_weights)?;

        if let BranchChangesType::AppendNode = &changes.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(changes, &mut fork)?;

        self.update_path_secrets(artefact_secrets, &changes.node_index, append_changes)?;

        Ok(())
    }

    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError> {
        let old_secrets = self.get_path_secrets().clone();

        self.recompute_path_secrets_for_participant(target_changes, self.clone())?;

        // subtract default secrets from path_secrets
        let path_secrets = self.get_mut_path_secrets();
        for i in (0..old_secrets.len()).rev() {
            if path_secrets[i] != old_secrets[i] {
                path_secrets[i] -= old_secrets[i];
            } else {
                return Ok(());
            }
        }

        Ok(())
    }

    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &[BranchChanges<G>],
        base_fork: A,
    ) -> Result<(), ARTError> {
        for change in target_changes {
            let mut fork = base_fork.clone();

            if self.get_node_index().is_subpath_of(&change.node_index)? {
                match change.change_type {
                    BranchChangesType::MakeBlank => return Err(ARTError::InapplicableBlanking),
                    BranchChangesType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                    BranchChangesType::AppendNode => {
                        // Extend path_secrets. Append additional leaf secret to the start.
                        let mut new_path_secrets =
                            vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                        new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                        self.set_path_secrets(new_path_secrets);
                    }
                }
            }

            let secrets = self.get_artefact_secrets_from_change(change, &mut fork)?;

            self.update_path_secrets(secrets, &change.node_index, true)?;
        }

        Ok(())
    }

    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChanges<G>,
        fork: &mut Self,
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        fork.update_public_art_with_options(changes, false, true)?;
        if let BranchChangesType::AppendNode = &changes.change_type {
            fork.update_node_index()?;
        };

        let co_path_values = fork.get_co_path_values(fork.get_node_index())?;
        let mut secrets = Vec::with_capacity(co_path_values.len() + 1);
        secrets.push(fork.get_secret_key());
        let mut ark_secret = fork.get_secret_key();
        for public_key in co_path_values.iter() {
            ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            secrets.push(ark_secret);
        }

        Ok(secrets)
    }
}
