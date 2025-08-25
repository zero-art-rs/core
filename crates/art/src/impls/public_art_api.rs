use crate::{
    errors::ARTError,
    helper_tools::iota_function,
    traits::{ARTPublicAPI, ARTPublicView},
    types::{
        ARTNode, ARTRootKey, BranchChanges, BranchChangesType, Direction, LeafIterWithPath,
        NodeIndex, NodeIterWithPath, ProverArtefacts, VerifierArtefacts,
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::cmp::{max, min};
use std::collections::HashMap;

impl<G, A> ARTPublicAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G>,
{
    fn get_co_path_values(&self, path: &[Direction]) -> Result<Vec<G>, ARTError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in path {
            match direction {
                Direction::Left => {
                    co_path_values.push(parent.get_right()?.public_key);
                    parent = parent.get_left()?;
                }
                Direction::Right => {
                    co_path_values.push(parent.get_left()?.public_key);
                    parent = parent.get_right()?;
                }
            }
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

        Err(ARTError::PathNotExists)
    }

    fn get_leaf_index(&self, user_val: &G) -> Result<u32, ARTError> {
        let next = self.get_path_to_leaf(user_val)?;

        Ok(NodeIndex::get_index_from_path(&next)?)
    }

    fn recompute_root_key_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<ARTRootKey<G>, ARTError> {
        let path = match node_index {
            Some(node_index) => node_index.get_path()?,
            None => self.get_path_to_leaf(&self.public_key_of(&secret_key))?,
        };

        let co_path_values = self.get_co_path_values(&path)?;

        let mut ark_secret = secret_key.clone();
        for public_key in co_path_values.iter() {
            let secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
        }

        Ok(ARTRootKey {
            key: ark_secret,
            generator: self.get_generator().clone(),
        })
    }

    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError> {
        let path = match node_index {
            Some(node_index) => node_index.get_path()?,
            None => self.get_path_to_leaf(&self.public_key_of(&secret_key))?,
        };

        let co_path_values = self.get_co_path_values(&path)?;

        let mut ark_secret = secret_key.clone();
        let mut secrets: Vec<Scalar> = vec![Scalar::from_bytes_mod_order(
            (&secret_key.clone().into_bigint().to_bytes_le()[..]).try_into()?,
        )];
        let mut path_values: Vec<G> = vec![G::generator().mul(ark_secret).into_affine()];
        for public_key in co_path_values.iter() {
            let secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            secrets.push(secret.clone());
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
            path_values.push(G::generator().mul(ark_secret).into_affine());
        }

        Ok((
            ARTRootKey {
                key: ark_secret,
                generator: self.get_generator().clone(),
            },
            ProverArtefacts {
                path: path_values,
                co_path: co_path_values,
                secrets,
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

    fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &[Direction],
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let mut next = path.to_vec();

        let mut changes = BranchChanges {
            change_type: BranchChangesType::UpdateKey,
            public_keys: Vec::new(),
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(&next.clone())?),
        };

        let mut public_key = self.public_key_of(secret_key);

        let mut ark_level_secret_key = secret_key.clone();
        while let Some(next_child) = next.pop() {
            let mut parent = self.get_mut_root();
            for direction in &next {
                parent = parent.get_mut_child(direction)?;
            }

            parent
                .get_mut_child(&next_child)?
                .set_public_key(public_key);

            changes.public_keys.push(public_key);

            let other_child_public_key = parent.get_other_child(&next_child)?.public_key.clone();
            let common_secret = other_child_public_key
                .mul(ark_level_secret_key)
                .into_affine();
            let level_secret_key = iota_function(&common_secret)?;
            ark_level_secret_key =
                G::ScalarField::from_le_bytes_mod_order(&level_secret_key.to_bytes());
            public_key = self
                .get_generator()
                .mul(&ark_level_secret_key)
                .into_affine();
        }

        self.get_mut_root().set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: ark_level_secret_key,
            generator: self.get_generator().clone(),
        };

        Ok((key, changes))
    }

    fn update_key_with_secret_key(
        &mut self,
        node_index: &NodeIndex,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let new_public_key = self.public_key_of(new_secret_key);

        let user_node = self.get_mut_node(node_index)?;
        user_node.set_public_key(new_public_key);

        self.update_art_with_secret_key(&new_secret_key, &node_index.get_path()?)
    }

    fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, ARTError> {
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

    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &[Direction],
    ) -> Result<Option<Direction>, ARTError> {
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
            true => None,
            false => Some(Direction::Right),
        };
        node_for_extension.extend_or_replace(node)?;

        Ok(next_node_direction)
    }

    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let mut path = self.find_path_to_possible_leaf_for_insertion()?;
        let node = ARTNode::new_leaf(self.public_key_of(secret_key));

        let next = self.append_node_without_changes(node.clone(), &path)?;
        match next {
            Some(Direction::Right) => path.push(Direction::Right),
            Some(Direction::Left) => return Err(ARTError::ARTLogicError),
            None => {}
        }

        let node_index = NodeIndex::Index(NodeIndex::get_index_from_path(&path)?);
        self.update_art_with_secret_key(secret_key, &path)
            .map(|(root_key, mut changes)| {
                changes.node_index = node_index;
                changes.change_type = BranchChangesType::AppendNode;
                (root_key, changes)
            })
    }

    fn make_blank_without_changes(
        &mut self,
        path: &[Direction],
        temporary_public_key: &G,
    ) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }
        target_node.make_blank(temporary_public_key)?;

        Ok(())
    }

    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let next = self.get_path_to_leaf(public_key)?;

        self.make_blank_without_changes(&next, &self.public_key_of(temporary_secret_key))?;

        self.update_art_with_secret_key(temporary_secret_key, &next)
            .map(|(root_key, mut changes)| {
                changes.change_type = BranchChangesType::MakeBlank;
                (root_key, changes)
            })
    }

    fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        let mut current_node = self.get_mut_root();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key(changes.public_keys[i]);
            current_node = current_node.get_mut_child(
                changes
                    .node_index
                    .get_path()?
                    .get(i)
                    .unwrap_or(&Direction::Right),
            )?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1]);

        Ok(())
    }

    fn update_art_with_changes_and_path(
        &mut self,
        changes: &BranchChanges<G>,
        path: &[Direction],
    ) -> Result<(), ARTError> {
        let mut current_node = self.get_mut_root();
        for (next, public_key) in path
            .iter()
            .zip(changes.public_keys[..changes.public_keys.len() - 1].iter())
        {
            current_node.set_public_key(*public_key);
            current_node = current_node.get_mut_child(next)?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1]);

        Ok(())
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
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        if !self.can_remove(lambda, public_key)? {
            return Err(ARTError::RemoveError);
        }

        let path = self.get_path_to_leaf(public_key)?;
        self.remove_node(&path)?;

        match self.update_art_with_secret_key(lambda, &path) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::RemoveNode;

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    fn min_max_leaf_height(&self) -> Result<(u32, u32), ARTError> {
        let mut min_height = u32::MAX;
        let mut max_height = u32::MIN;
        let root = self.get_root();

        for (_, path) in LeafIterWithPath::new(root) {
            min_height = min(min_height, path.len() as u32);
            max_height = max(max_height, path.len() as u32);
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(&self) -> Result<u32, ARTError> {
        let (min_height, max_height) = self.min_max_leaf_height()?;

        Ok(max_height - min_height)
    }

    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKey => self.update_art_with_changes(changes),
            BranchChangesType::AppendNode => {
                let leaf = ARTNode::new_leaf(
                    changes
                        .public_keys
                        .last()
                        .ok_or(ARTError::NoChanges)?
                        .clone(),
                );
                self.append_node_without_changes(leaf, &changes.node_index.get_path()?)?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::MakeBlank => {
                let temporary_public_key = changes.public_keys.last().ok_or(ARTError::NoChanges)?;
                self.make_blank_without_changes(
                    &changes.node_index.get_path()?,
                    temporary_public_key,
                )?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::RemoveNode => Err(ARTError::RemoveError),
        }
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
                // The last node weight where computed when structure where updated
            }

            if shared_paths.is_empty() {
                // There are no further conflicts
                node.public_key = target_change.public_keys[level];
            } else {
                // Resolve conflict
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

                let subtree = match node.is_blank {
                    true => ARTNode::new_default_tree_with_public_keys(subtree_leaves)?,
                    false => {
                        let mut subtree_with_previous_user = vec![node.public_key];
                        subtree_with_previous_user.extend(subtree_leaves);

                        ARTNode::new_default_tree_with_public_keys(&subtree_with_previous_user)?
                    }
                };

                node.replace_with(subtree);
            }
        }

        // merge all add member changes as key update, as all the nodes are present
        // for i in 0..update_key_changes.len() {
        //     self.merge_key_update(&update_key_changes[0..i].to_vec(), &update_key_changes[i])?;
        // }

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
                BranchChangesType::UpdateKey => {}
                _ => return Err(ARTError::InvalidInput),
            }
        }

        let mut update_key_changes = Vec::new();
        let mut append_member_changes = Vec::new();

        for change in target_changes {
            match change.change_type {
                BranchChangesType::UpdateKey => {
                    update_key_changes.push(change.clone());
                }
                BranchChangesType::AppendNode => {
                    append_member_changes.push(change.clone());
                }
                _ => todo!(),
            }
        }

        self.prepare_structure_for_append_node_changes(append_member_changes.as_slice())?;

        // merge all key update changes but skip whose from applied_changes
        let merge_limit = update_key_changes.len();
        let mut changes = applied_changes.clone();
        changes.extend(update_key_changes);
        changes.extend(append_member_changes);

        for i in applied_changes.len()..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }

        Ok(())
    }
}
