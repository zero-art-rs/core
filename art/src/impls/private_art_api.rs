// Asynchronous Ratchet Tree implementation

use crate::errors::ARTNodeError;
use crate::helper_tools::iota_function;
use crate::traits::{ARTPrivateAPIHelper, ARTPublicAPI, ChildContainer};
use crate::types::{
    ARTNode, AggregationData, AggregationNodeIterWithPath, BranchChangesIter,
    BranchChangesTypeHint, ChangeAggregation, Direction, NodeIndex, ProverAggregationData,
    UpdateData, VerifierAggregationData,
};
use crate::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPIHelper},
    types::{ARTRootKey, BranchChanges, BranchChangesType, ProverArtefacts},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::CortadoAffine;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, error};

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
        let (tk, changes, artefacts) = self.make_blank(path, temporary_secret_key)?;

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::MakeBlank {
                blank_pk: self.public_key_of(temporary_secret_key),
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

        let hint = !self
            .get_node(&NodeIndex::Direction(path.to_vec()))?
            .is_blank;

        let (tk, changes, artefacts) = self.append_or_replace_node(secret_key)?;

        aggregation.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::AppendNode { extend: hint },
        )?;

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

    fn update_private_art_aggregation_v2(
        &mut self,
        verifier_aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
    ) -> Result<(), ARTError> {
        for mut changes in BranchChangesIter::new(verifier_aggregation) {
            for change in changes.iter_mut() {
                change.node_index = change.node_index.as_index()?;
                debug!("changes: {:#?}", change);
                self.update_private_art(&*change)?;
            }
        }

        Ok(())
    }

    fn update_private_art_aggregation(
        &mut self,
        verifier_aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
    ) -> Result<(), ARTError> {
        for (item, path) in AggregationNodeIterWithPath::new(verifier_aggregation) {
            let item_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            for change_type in &item.data.change_type {
                match change_type {
                    BranchChangesTypeHint::MakeBlank { .. } => {
                        for i in 0..item_path.len() {
                            let partial_path = item_path[0..i].to_vec();
                            self.get_mut_node(&NodeIndex::Direction(partial_path))?
                                .weight -= 1;
                        }

                        let corresponding_item =
                            self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.is_blank = true;
                    }
                    BranchChangesTypeHint::AppendNode { .. } => {
                        for i in 0..item_path.len() {
                            let partial_path = item_path[0..i].to_vec();
                            self.get_mut_node(&NodeIndex::Direction(partial_path))?
                                .weight += 1;
                        }

                        let corresponding_item =
                            self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        match corresponding_item.extend_or_replace(ARTNode::default()) {
                            Ok(_) => {}
                            Err(err) => {
                                return Err(ARTError::from(err));
                            }
                        }
                    }
                    BranchChangesTypeHint::UpdateKey { .. } => {}
                    BranchChangesTypeHint::AppendNodeFix => {}
                }
            }

            let corresponding_item = self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
            corresponding_item.public_key = item.data.public_key;
        }

        self.update_node_index()?;
        let (_, artefacts) = self.recompute_root_key_with_artefacts_using_secret_key(
            self.get_secret_key(),
            &self.get_node_index(),
        )?;

        self.set_path_secrets(artefacts.secrets);

        Ok(())
    }

    fn merge_for_observer(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError> {
        let mut append_member_count = 0;
        for change in target_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::MergeInput);
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
            return Err(ARTError::MergeInput);
        }

        let mut append_member_count = 0;
        for change in unapplied_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::MergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_participant(unapplied_changes, base_fork)?;
        self.merge_with_skip(&[applied_change], unapplied_changes)?;

        Ok(())
    }

    fn get_aggregation_co_path(
        &self,
        aggregation: &ChangeAggregation<AggregationData<G>>,
    ) -> Result<ChangeAggregation<VerifierAggregationData<G>>, ARTError> {
        let mut resulting_aggregation =
            ChangeAggregation::<VerifierAggregationData<G>>::derive_from(&aggregation)?;

        for (_, path) in AggregationNodeIterWithPath::new(aggregation).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let last_direction = parent_path.pop().ok_or(ARTError::NoChanges)?;

            let aggregation_parent = path
                .last()
                .ok_or(ARTError::NoChanges)
                .map(|(node, _)| node)?;

            let resulting_target_node = resulting_aggregation
                .get_mut_node(&parent_path)?
                .get_mut_node(&[last_direction])?;

            if let Ok(co_leaf) = aggregation_parent.get_node(&[last_direction.other()]) {
                // Retrieve co-path from the aggregation
                let pk = co_leaf.data.public_key;
                resulting_target_node.data.co_public_key = Some(pk);
            } else if let Ok(parent) = self.get_node(&NodeIndex::Direction(parent_path.clone()))
                && let Ok(other_child) = parent.get_child(&last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                resulting_target_node.data.co_public_key = Some(other_child.get_public_key());
            } else {
                // Find leaf in original art. There where no of his modifications as they are stored separately.
                let mut leaf_traversal = parent_path.clone();
                let mut leaf_pk = self.get_root().public_key;
                while !leaf_traversal.is_empty() {
                    if let Ok(leaf) = self.get_node(&NodeIndex::Direction(leaf_traversal.clone())) {
                        leaf_pk = leaf.public_key;
                        break;
                    }

                    let last_fir = leaf_traversal.pop().ok_or(ARTError::ARTLogicError)?;
                    if let Direction::Right = last_fir {
                        return Err(ARTError::InvalidInput);
                    }
                }

                resulting_target_node.data.co_public_key = Some(leaf_pk);
            }
        }

        Ok(resulting_aggregation)
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
