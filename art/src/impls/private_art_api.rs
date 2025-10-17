// Asynchronous Ratchet Tree implementation

use crate::errors::ARTError;
use crate::helper_tools::recompute_artefacts;
use crate::traits::{
    ARTPrivateAPI, ARTPrivateAPIHelper, ARTPrivateView, ARTPublicAPIHelper, ChildContainer,
};
use crate::types::{
    ARTRootKey, BranchChanges, BranchChangesType, BranchChangesTypeHint, ChangeAggregation,
    Direction, LeafStatus, NodeIndex, ProverAggregationData, ProverArtefacts, UpdateData,
    VerifierAggregationData,
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Serialize, de::DeserializeOwned};

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

        let (tk, changes, artefacts) = self.update_art_branch_with_leaf_secret_key(
            new_secret_key,
            &self.get_node_index().get_path()?,
            false,
        )?;

        self.set_path_secrets(artefacts.secrets.clone());
        self.update_node_index()?;

        Ok((tk, changes, artefacts))
    }

    fn make_blank(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let append_changes = matches!(
            self.get_node_with_path(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
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

    fn leave(&mut self, new_secret_key: G::ScalarField) -> Result<UpdateData<G>, ARTError> {
        let (tk, mut changes, artefacts) = self.update_key(&new_secret_key)?;
        let index = self.get_node_index().clone();
        self.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        changes.change_type = BranchChangesType::Leave;

        Ok((tk, changes, artefacts))
    }

    fn update_key_and_aggregate(
        &mut self,
        new_secret_key: &G::ScalarField,
        aggregation: &mut ChangeAggregation<ProverAggregationData<G>>,
    ) -> Result<UpdateData<G>, ARTError> {
        let (tk, changes, artefacts) = self.update_key(new_secret_key)?;

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::UpdateKey {
                pk: self.public_key_of(new_secret_key),
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    fn make_blank_and_aggregate(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
        aggregation: &mut ChangeAggregation<ProverAggregationData<G>>,
    ) -> Result<UpdateData<G>, ARTError> {
        let merge = matches!(
            self.get_node_with_path(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        if merge {
            return Err(ARTError::InvalidMergeInput);
        }

        let (tk, changes, artefacts) = self.make_blank(path, temporary_secret_key)?;

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::MakeBlank {
                pk: self.public_key_of(temporary_secret_key),
                merge,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    fn append_or_replace_node_and_aggregate(
        &mut self,
        secret_key: &G::ScalarField,
        aggregation: &mut ChangeAggregation<ProverAggregationData<G>>,
    ) -> Result<UpdateData<G>, ARTError> {
        let path = match self.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => self.find_path_to_lowest_leaf()?,
        };

        let hint = self
            .get_node(&NodeIndex::Direction(path.to_vec()))?
            .is_active();

        let (tk, changes, artefacts) = self.append_or_replace_node(secret_key)?;

        let ext_pk = match hint {
            true => Some(
                self.get_node(&NodeIndex::Direction(path.to_vec()))?
                    .get_public_key(),
            ),
            false => None,
        };

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::AppendNode {
                pk: self.public_key_of(secret_key),
                ext_pk,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    fn leave_and_aggregate(
        &mut self,
        new_secret_key: &G::ScalarField,
        aggregation: &mut ChangeAggregation<ProverAggregationData<G>>,
    ) -> Result<UpdateData<G>, ARTError> {
        let (tk, changes, artefacts) = self.leave(*new_secret_key)?;

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::Leave {
                pk: self.public_key_of(new_secret_key),
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    fn update_private_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && matches!(
                self.get_node(&changes.node_index)?.get_status(),
                Some(LeafStatus::Blank)
            )
        {
            self.update_private_art_with_options(changes, true, false)
        } else {
            self.update_private_art_with_options(changes, false, true)
        }
    }

    fn update_private_art_with_aggregation(
        &mut self,
        verifier_aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
    ) -> Result<(), ARTError> {
        self.update_public_art_with_aggregation(verifier_aggregation)?;

        self.update_node_index()?;
        self.update_path_secrets_with_aggregation_tree(&verifier_aggregation)?;

        Ok(())
    }

    fn merge_for_observer(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError> {
        let mut append_member_count = 0;
        for change in target_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_observer(target_changes)?;
        self.merge_all(target_changes)?;

        Ok(())
    }

    fn merge_for_participant(
        &mut self,
        applied_change: BranchChanges<G>,
        unapplied_changes: &[BranchChanges<G>],
        base_fork: Self,
    ) -> Result<(), ARTError> {
        // Currently, it will fail if the first applied change is append_member.
        if let BranchChangesType::AppendNode = applied_change.change_type {
            return Err(ARTError::InvalidMergeInput);
        }

        let mut append_member_count = 0;
        for change in unapplied_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_participant(unapplied_changes, base_fork)?;
        self.merge_with_skip(&[applied_change], unapplied_changes)?;

        Ok(())
    }
}

impl<G, A> ARTPrivateAPIHelper<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPrivateView<G> + ARTPublicAPIHelper<G>,
{
    fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self.get_path_to_leaf(&self.public_key_of(&self.get_secret_key()))?;
        self.set_node_index(NodeIndex::Direction(path).as_index()?);

        Ok(())
    }

    fn update_path_secrets(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if self.get_node_index().is_subpath_of(other)? {
            return Err(ARTError::InvalidInput);
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // Always update art root key.
        match append_changes {
            true => path_secrets[0] += other_path_secrets[0],
            false => path_secrets[0] = other_path_secrets[0],
        }

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                match append_changes {
                    true => path_secrets[i + 1] += other_path_secrets[i + 1],
                    false => path_secrets[i + 1] = other_path_secrets[i + 1],
                }
            } else {
                break;
            }
        }

        // Reverse path_secrets back to normal order, and update change old secrets.
        path_secrets.reverse();
        self.set_path_secrets(path_secrets);

        Ok(())
    }

    fn update_path_secrets_with_aggregation_tree(
        &mut self,
        aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
    ) -> Result<(), ARTError> {
        let path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if aggregation.contain(&self.get_node_index().get_path()?) {
            return Err(ARTError::InvalidInput);
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let mut intersection = aggregation.get_intersection(&node_path);

        let mut partial_co_path = Vec::new();
        let mut current_art_node = self.get_root();
        let mut current_agg_node = aggregation;
        let mut add_member_counter = current_agg_node
            .data
            .change_type
            .iter()
            .filter(|change| matches!(change, BranchChangesTypeHint::AppendNode { .. }))
            .count();
        for dir in &intersection {
            partial_co_path.push(current_art_node.get_child(&dir.other())?.get_public_key());

            current_art_node = current_art_node.get_child(dir)?;
            current_agg_node = current_agg_node
                .children
                .get_child(*dir)
                .ok_or(ARTError::PathNotExists)?;

            add_member_counter += current_agg_node
                .data
                .change_type
                .iter()
                .filter(|change| matches!(change, BranchChangesTypeHint::AppendNode { .. }))
                .count();
        }

        intersection.push(node_path[intersection.len()].other());
        partial_co_path.push(aggregation.get_node(&*intersection)?.data.public_key);
        partial_co_path.reverse();

        // Compute path_secrets for aggregation.
        let resulting_path_secrets_len = self.get_path_secrets().len() + add_member_counter;
        let index = resulting_path_secrets_len - partial_co_path.len() - 1;
        let level_sk = self.get_path_secrets()[index];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, &partial_co_path)?;

        let mut new_path_secrets = self.get_path_secrets().clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        // Update node `path_secrets`
        self.set_path_secrets(new_path_secrets);

        Ok(())
    }

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
                BranchChangesType::Leave => return Err(ARTError::InapplicableLeave),
                BranchChangesType::AppendNode => {
                    // Extend path_secrets. Append additional leaf secret to the start.
                    let mut new_path_secrets =
                        vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                    new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                    self.set_path_secrets(new_path_secrets);
                }
            }
        }

        self.update_public_art_with_options(changes, append_changes, update_weights)?;

        if let BranchChangesType::AppendNode = &changes.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(changes)?;

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
            if self.get_node_index().is_subpath_of(&change.node_index)? {
                match change.change_type {
                    BranchChangesType::MakeBlank => return Err(ARTError::InapplicableBlanking),
                    BranchChangesType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                    BranchChangesType::Leave => return Err(ARTError::InapplicableLeave),
                    BranchChangesType::AppendNode => {
                        // Extend path_secrets. Append additional leaf secret to the start.
                        let mut new_path_secrets =
                            vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                        new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                        self.set_path_secrets(new_path_secrets);
                    }
                }
            }

            let secrets = base_fork.get_artefact_secrets_from_change(change)?;

            self.update_path_secrets(secrets, &change.node_index, true)?;
        }

        Ok(())
    }

    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChanges<G>,
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        let intersection = self.get_node_index().intersect_with(&changes.node_index)?;

        let mut co_path = Vec::new();
        let mut current_node = self.get_root();
        for dir in &intersection {
            co_path.push(current_node.get_child(&dir.other())?.get_public_key());
            current_node = current_node.get_child(dir)?;
        }

        if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
            co_path.push(*public_key);
        }

        co_path.reverse();

        let secrets = self.get_partial_path_secrets(&co_path)?;

        Ok(secrets)
    }

    fn get_partial_path_secrets(
        &self,
        partial_co_path: &[G],
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        let path_length = self.get_path_secrets().len();
        let updated_path_len = partial_co_path.len();

        let level_sk = self.get_path_secrets()[path_length - updated_path_len - 1];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, partial_co_path)?;

        let mut new_path_secrets = self.get_path_secrets().clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        Ok(new_path_secrets)
    }
}
