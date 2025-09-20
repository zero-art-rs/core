// Asynchronous Ratchet Tree implementation

use crate::helper_tools::{iota_function};
use crate::types::{Direction, NodeIndex};
use crate::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, BranchChangesType, ProverArtefacts},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::debug;

impl<G, A> ARTPrivateAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPrivateView<G>,
{
    fn recompute_prover_artefacts(&self) -> Result<ProverArtefacts<G>, ARTError> {
        let (_, artefacts) = self
            .recompute_root_key_with_artefacts_using_path_secrets(
                self.get_node_index(),
                self.get_path_secrets().clone()
            )?;

        Ok(artefacts)
    }

    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        Ok(ARTRootKey {
            key: *self
                    .get_path_secrets()
                    .last()
                    .ok_or(ARTError::ARTLogicError)?,
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
        path: &Vec<Direction>,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let append_changes = self.get_node(&NodeIndex::from(path.clone()))?.is_blank;
        let (mut tk, changes, artefacts) = self.make_blank_in_public_art(
            path,
            temporary_secret_key,
        )?;

        match append_changes {
            true => {
                self.merge_path_secrets(&artefacts.secrets, &changes.node_index)?;
                tk.key += *self.get_path_secrets().last().ok_or(ARTError::EmptyART)?;
            }
            false => _ = self.set_path_secrets(artefacts.secrets.clone()),
        }

        Ok((tk, changes, artefacts))
    }

    fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let (tk, changes, artefacts) = self.append_or_replace_node_in_public_art(secret_key)?;
        self.update_path_secrets_with(artefacts.secrets.clone(), &changes.node_index)?;
        self.update_node_index()?;

        Ok((tk, changes, artefacts))
    }

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type && self.get_node(&changes.node_index)?.is_blank {
            self.update_private_art_with_options(changes, true, false)
        } else {
            self.update_private_art_with_options(changes, false, true)
        }
    }

    fn update_private_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        let fork = self.clone();
        self.update_public_art_with_options(changes, append_changes, update_weights)?;

        if let BranchChangesType::AppendNode = &changes.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(
            self.get_node_index(),
            self.get_secret_key(),
            changes,
            fork,
        )?;

        match append_changes {
            true => self.merge_path_secrets(&artefact_secrets, &changes.node_index)?,
            false => self.update_path_secrets_with(artefact_secrets, &changes.node_index)?,
        }

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
                path_secrets[i] = path_secrets[i] - old_secrets[i];
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
            secrets.push(fork.get_secret_key());
            let mut ark_secret = fork.get_secret_key();
            for public_key in co_path_values.iter() {
                ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
                secrets.push(ark_secret);
            }

            self.merge_path_secrets(&secrets, &change.node_index)?;
        }

        Ok(())
    }
}
