use crate::traits::ARTPrivateAPI;
use crate::{
    errors::ARTError,
    helper_tools::{iota_function, to_ark_scalar, to_dalek_scalar},
    traits::{ARTPublicAPI, ARTPublicView},
    types::{
        ARTNode, ARTRootKey, BranchChanges, BranchChangesType, Direction, LeafIterWithPath,
        NodeIndex, NodeIterWithPath, ProverArtefacts, VerifierArtefacts,
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::cmp::{max, min};
use std::collections::HashMap;
use tracing::{debug, error};

impl<G, A> ARTPublicAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G>,
{
    fn get_co_path_values(&self, index: &NodeIndex) -> Result<Vec<G>, ARTError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in &index.get_path()? {
            co_path_values.push(parent.get_other_child(direction)?.public_key);
            parent = parent.get_child(direction)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    fn get_path_to_leaf(&self, user_val: &G) -> Result<Vec<Direction>, ARTError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.public_key.eq(user_val) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        error!("Failed to find a path to the node, as it isn't exists");
        Err(ARTError::PathNotExists)
    }

    fn get_leaf_index(&self, user_val: &G) -> Result<u64, ARTError> {
        Ok(NodeIndex::get_index_from_path(
            &self.get_path_to_leaf(user_val)?,
        )?)
    }

    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: &NodeIndex,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError> {
        let co_path_values = self.get_co_path_values(node_index)?;

        let mut ark_secret = secret_key.clone();
        let mut secrets: Vec<G::ScalarField> = vec![secret_key];
        let mut path_values: Vec<G> = vec![G::generator().mul(ark_secret).into_affine()];
        for public_key in co_path_values.iter() {
            ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            secrets.push(ark_secret.clone());
            path_values.push(G::generator().mul(ark_secret).into_affine());
        }

        Ok((
            ARTRootKey {
                key: ark_secret,
                generator: self.get_generator(),
            },
            ProverArtefacts {
                path: path_values,
                co_path: co_path_values,
                secrets,
            },
        ))
    }

    fn recompute_root_key_with_artefacts_using_path_secrets(
        &self,
        node_index: &NodeIndex,
        path_secrets: Vec<G::ScalarField>,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError> {
        let co_path_values = self.get_co_path_values(&node_index)?;
        if co_path_values.len() != path_secrets.len() {
            return Err(ARTError::InvalidInput);
        }

        let mut path_values = Vec::with_capacity(co_path_values.len());
        for (sk, pk) in path_secrets.iter().zip(co_path_values.iter()) {
            path_values.push(pk.mul(sk).into_affine());
        }

        Ok((
            ARTRootKey {
                key: *path_secrets.last().ok_or(ARTError::InvalidInput)?,
                generator: self.get_generator(),
            },
            ProverArtefacts {
                path: path_values,
                co_path: co_path_values,
                secrets: path_secrets,
            },
        ))
    }

    fn compute_artefacts_for_verification(
        &self,
        changes: &BranchChanges<G>,
    ) -> Result<VerifierArtefacts<G>, ARTError> {
        let mut co_path = Vec::new();

        let mut parent = self.get_root();
        for direction in &changes.node_index.get_path()? {
            if parent.is_leaf() {
                if let BranchChangesType::AppendNode = changes.change_type
                    && !parent.is_blank
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.public_key)
                }
            } else {
                co_path.push(parent.get_other_child(direction)?.public_key);
                parent = parent.get_child(direction)?;
            }
        }

        co_path.reverse();

        Ok(VerifierArtefacts {
            path: changes.public_keys.iter().rev().cloned().collect(),
            co_path,
        })
    }

    fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.get_generator().mul(secret).into_affine()
    }

    fn update_art_branch_with_leaf_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &[Direction],
        append_changes: bool,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let mut next = path.to_vec();
        let mut public_key = self.public_key_of(secret_key);

        let mut co_path_values = vec![];
        let mut path_values = vec![];
        let mut secrets = vec![*secret_key];

        let mut ark_level_secret_key = *secret_key;
        while let Some(next_child) = next.pop() {
            let mut parent = self.get_mut_root();
            for direction in &next {
                parent = parent.get_mut_child(direction)?;
            }

            // Update public art
            parent
                .get_mut_child(&next_child)?
                .set_public_key_with_options(public_key, append_changes);
            let other_child_public_key = parent.get_other_child(&next_child)?.public_key.clone();

            path_values.push(public_key);
            co_path_values.push(other_child_public_key);

            let common_secret = other_child_public_key
                .mul(ark_level_secret_key)
                .into_affine();

            ark_level_secret_key = iota_function(&common_secret)?;
            secrets.push(ark_level_secret_key);

            public_key = self.public_key_of(&ark_level_secret_key);
        }

        self.get_mut_root()
            .set_public_key_with_options(public_key, append_changes);
        path_values.push(public_key);

        let key = ARTRootKey {
            key: ark_level_secret_key,
            generator: self.get_generator(),
        };

        let artefacts = ProverArtefacts {
            path: path_values.clone(),
            co_path: co_path_values,
            secrets,
        };

        path_values.reverse();

        let changes = BranchChanges {
            change_type: BranchChangesType::UpdateKey,
            public_keys: path_values,
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(&path.to_vec())?),
        };

        Ok((key, changes, artefacts))
    }

    fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in LeafIterWithPath::new(self.get_root()) {
            if node.is_blank {
                let mut node_path = Vec::with_capacity(path.len());

                for (_, dir) in path {
                    node_path.push(dir);
                }

                return Some(node_path);
            }
        }

        None
    }

    fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ARTError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate.get_left()?;
            let r = candidate.get_right()?;

            match l.weight <= r.weight {
                true => {
                    next.push(Direction::Left);
                    candidate = candidate.get_left()?;
                }
                false => {
                    next.push(Direction::Right);
                    candidate = candidate.get_right()?;
                }
            }
        }

        Ok(next)
    }

    fn append_or_replace_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &[Direction],
    ) -> Result<bool, ARTError> {
        let mut node_for_extension = self.get_mut_root();
        for direction in path {
            if node_for_extension.is_leaf() {
                // The last node weight is done automatically through the extension method in ARTNode
                break;
            }

            node_for_extension.weight += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension.get_mut_child(direction)?;
        }
        let next_node_direction = match node_for_extension.is_blank {
            true => false,
            false => true,
        };
        node_for_extension.extend_or_replace(node)?;

        Ok(next_node_direction)
    }

    fn append_or_replace_node_in_public_art(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let mut path = match self.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => self.find_path_to_lowest_leaf()?,
        };

        let node = ARTNode::new_leaf(self.public_key_of(secret_key));

        let extend_path = self.append_or_replace_node_without_changes(node.clone(), &path)?;
        if extend_path {
            path.push(Direction::Right);
        }

        let node_index = NodeIndex::Index(NodeIndex::get_index_from_path(&path)?);
        self.update_art_branch_with_leaf_secret_key(secret_key, &path, false)
            .map(|(root_key, mut changes, artefacts)| {
                changes.node_index = node_index;
                changes.change_type = BranchChangesType::AppendNode;
                (root_key, changes, artefacts)
            })
    }

    fn make_blank_without_changes_with_options(
        &mut self,
        path: &[Direction],
        update_weights: bool,
    ) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            if update_weights {
                target_node.weight -= 1;
            }
            target_node = target_node.get_mut_child(direction)?;
        }

        target_node.is_blank = true;

        Ok(())
    }

    fn make_blank_in_public_art(
        &mut self,
        path: &Vec<Direction>,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let (append_changes, update_weights) =
            match self.get_node(&NodeIndex::from(path.clone()))?.is_blank {
                true => (true, false),
                false => (false, true),
            };

        self.make_blank_without_changes_with_options(&path, update_weights)?;

        self.update_art_branch_with_leaf_secret_key(temporary_secret_key, &path, append_changes)
            .map(|(root_key, mut changes, artefacts)| {
                changes.change_type = BranchChangesType::MakeBlank;
                (root_key, changes, artefacts)
            })
    }

    fn update_art_with_changes(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        if changes.public_keys.len() == 0 {
            return Err(ARTError::InvalidInput);
        }

        let mut current_node = self.get_mut_root();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key_with_options(changes.public_keys[i], append_changes);
            current_node = current_node.get_mut_child(
                changes
                    .node_index
                    .get_path()?
                    .get(i)
                    .unwrap_or(&Direction::Right),
            )?;
        }

        current_node.set_public_key_with_options(
            changes.public_keys[changes.public_keys.len() - 1],
            append_changes,
        );

        Ok(())
    }

    fn get_artefact_secrets_from_change(
        &self,
        node_index: &NodeIndex,
        secret_key: G::ScalarField,
        changes: &BranchChanges<G>,
        mut fork: Self,
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        fork.update_public_art_with_options(changes, false, true)?;

        let co_path_values = fork.get_co_path_values(&node_index)?;
        let mut secrets = Vec::with_capacity(co_path_values.len() + 1);
        secrets.push(secret_key);
        let mut ark_secret = secret_key;
        for public_key in co_path_values.iter() {
            ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            secrets.push(ark_secret);
        }

        Ok(secrets)
    }

    fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError> {
        let mut node = self.get_root();
        for direction in &index.get_path()? {
            node = node.get_child(direction)?;
        }

        Ok(node)
    }

    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError> {
        let mut node = self.get_mut_root();
        for direction in &index.get_path()? {
            node = node.get_mut_child(direction)?;
        }

        Ok(node)
    }

    fn can_remove(&mut self, lambda: &G::ScalarField, public_key: &G) -> Result<bool, ARTError> {
        let users_public_key = self.public_key_of(lambda);

        if users_public_key.eq(public_key) {
            return Ok(false);
        }

        let path_to_other = self.get_path_to_leaf(public_key)?;
        let path_to_self = self.get_path_to_leaf(&users_public_key)?;

        if path_to_other.len() < 2 {
            return Ok(true);
        }

        if path_to_other.len().abs_diff(path_to_self.len()) > 1 {
            return Ok(false);
        }

        for i in 0..(max(path_to_self.len(), path_to_other.len()) - 2) {
            if path_to_self[i] != path_to_other[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn remove_node(&mut self, path: &[Direction]) -> Result<(), ARTError> {
        if path.len() == 0 {
            return Err(ARTError::InvalidInput);
        }

        let mut target_node = self.get_mut_root();
        for direction in &path[..path.len() - 1] {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }

        target_node.shrink_to_other(path[path.len() - 1])?;

        Ok(())
    }

    fn remove_node_and_update_tree(
        &mut self,
        lambda: &G::ScalarField,
        public_key: &G,
        append_changes: bool,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        if !self.can_remove(lambda, public_key)? {
            return Err(ARTError::RemoveError);
        }

        let path = self.get_path_to_leaf(public_key)?;
        self.remove_node(&path)?;

        match self.update_art_branch_with_leaf_secret_key(lambda, &path, append_changes) {
            Ok((root_key, mut changes, artefacts)) => {
                changes.change_type = BranchChangesType::RemoveNode;

                Ok((root_key, changes, artefacts))
            }
            Err(msg) => Err(msg),
        }
    }

    fn min_max_leaf_height(&self) -> Result<(u64, u64), ARTError> {
        let mut min_height = u64::MAX;
        let mut max_height = u64::MIN;
        let root = self.get_root();

        for (_, path) in LeafIterWithPath::new(root) {
            min_height = min(min_height, path.len() as u64);
            max_height = max(max_height, path.len() as u64);
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(&self) -> Result<u64, ARTError> {
        let (min_height, max_height) = self.min_max_leaf_height()?;

        Ok(max_height - min_height)
    }

    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && self.get_node(&changes.node_index)?.is_blank
        {
            self.update_public_art_with_options(changes, true, false)
        } else {
            self.update_public_art_with_options(changes, false, true)
        }
    }

    fn update_public_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKey => {}
            BranchChangesType::AppendNode => {
                let leaf = ARTNode::new_leaf(
                    changes
                        .public_keys
                        .last()
                        .ok_or(ARTError::NoChanges)?
                        .clone(),
                );
                self.append_or_replace_node_without_changes(leaf, &changes.node_index.get_path()?)?;
            }
            BranchChangesType::MakeBlank => {
                self.make_blank_without_changes_with_options(
                    &changes.node_index.get_path()?,
                    update_weights,
                )?;
            }
            BranchChangesType::RemoveNode => return Err(ARTError::RemoveError),
        }

        self.update_art_with_changes(changes, append_changes)
    }

    fn merge_change(
        &mut self,
        merged_changes: &[BranchChanges<G>],
        target_change: &BranchChanges<G>,
    ) -> Result<(), ARTError> {
        let mut shared_paths = Vec::with_capacity(merged_changes.len());
        for change in merged_changes {
            shared_paths.push(change.node_index.get_path()?);
        }

        let target_path = target_change.node_index.get_path()?;
        for level in 0..=target_path.len() {
            let node = self.get_mut_node(&NodeIndex::Direction(target_path[0..level].to_vec()))?;
            if let BranchChangesType::AppendNode = target_change.change_type {
                if level < target_path.len() {
                    node.weight += 1;
                }
                // The last node weight will be computed when the structure is updated
            }

            if shared_paths.is_empty() {
                // There are no further conflicts so change public key
                node.public_key = target_change.public_keys[level];
            } else {
                // Resolve conflict by adding public keys
                node.public_key =
                    (node.public_key + target_change.public_keys[level]).into_affine();
            }

            // Remove branches which are not conflicting with target one yet
            for j in (0..shared_paths.len()).rev() {
                if shared_paths[j].get(level) != target_path.get(level) {
                    shared_paths.remove(j);
                }
            }
        }

        Ok(())
    }

    fn prepare_structure_for_append_node_changes(
        &mut self,
        append_node_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError> {
        let mut update_targets = HashMap::new();
        for change in append_node_changes {
            update_targets
                .entry(change.node_index.get_path()?)
                .or_insert(Vec::new())
                .push(*change.public_keys.last().ok_or(ARTError::NoChanges)?);
        }

        // Sort public keys by x coordinate or, if they are equal, by y coordinate
        let keys = update_targets.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            update_targets
                .entry(key.clone())
                .and_modify(|subtree_leaves| {
                    subtree_leaves.sort_by(|&a, &b| match a.x() == b.x() {
                        false => return a.x().cmp(&b.x()),
                        true => a.y().cmp(&b.y()),
                    });
                });
        }

        for (path, subtree_leaves) in &mut update_targets.iter() {
            let mut target_node_path = path.clone();

            if let Some(last_dir) = target_node_path.pop() {
                let mut node = self.get_mut_node(&NodeIndex::Direction(target_node_path))?;
                node = match node.is_leaf() {
                    true => node,
                    false => node.get_mut_child(&last_dir)?,
                };

                node.extend_or_replace(ARTNode::new_default_tree_with_public_keys(
                    subtree_leaves,
                )?)?;
            }
        }

        Ok(())
    }

    fn merge(&mut self, target_changes: &Vec<BranchChanges<G>>) -> Result<(), ARTError> {
        self.merge_with_skip(&vec![], target_changes)
    }

    fn merge_with_skip(
        &mut self,
        applied_changes: &Vec<BranchChanges<G>>,
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError> {
        for change in applied_changes {
            match change.change_type {
                BranchChangesType::UpdateKey | BranchChangesType::MakeBlank => {}
                _ => return Err(ARTError::InvalidInput),
            }
        }

        let mut non_structural_changes = Vec::new();
        let mut append_member_changes = Vec::new();

        for change in target_changes {
            match change.change_type {
                BranchChangesType::UpdateKey | BranchChangesType::MakeBlank => {
                    non_structural_changes.push(change.clone());
                }
                BranchChangesType::AppendNode => {
                    append_member_changes.push(change.clone());
                }
                // Return error, as other operations are not supported for merge
                _ => return Err(ARTError::InvalidInput),
            }
        }

        // merge all key update changes but skip whose from applied_changes
        let merge_limit = non_structural_changes.len() + applied_changes.len();
        let mut changes = applied_changes.clone();
        changes.extend(non_structural_changes);

        for i in applied_changes.len()..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }

        self.prepare_structure_for_append_node_changes(append_member_changes.as_slice())?;
        changes.extend(append_member_changes);

        for i in merge_limit..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }

        Ok(())
    }
}
