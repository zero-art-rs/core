use crate::errors::ARTError;
use crate::helper_tools::iota_function;
use crate::traits::ParentRepr;
use crate::types::{
    ARTNode, ARTRootKey, AggregationData, BranchChanges, BranchChangesType, BranchChangesTypeHint,
    ChangeAggregationNode, Direction, LeafIterWithPath, LeafStatus, NodeIndex, NodeIterWithPath,
    PrivateART, ProverArtefacts, PublicART, VerifierArtefacts,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use std::collections::HashMap;
use std::mem;

pub(crate) type ArtLevel<G> = (Vec<ARTNode<G>>, Vec<<G as AffineRepr>::ScalarField>);

impl<G> PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    /// Computes the ART assuming that `level_nodes` and `level_secrets` are a power of two. If
    /// they are not they can be lifted with `fit_leaves_in_one_level` method.
    pub fn compute_next_layer_of_tree(
        level_nodes: Vec<Box<ARTNode<G>>>,
        level_secrets: &mut [G::ScalarField],
        generator: &G,
    ) -> Result<(Box<ARTNode<G>>, G::ScalarField), ARTError> {
        let mut stack = Vec::with_capacity(level_nodes.len());

        let mut last_secret = G::ScalarField::zero();

        // stack contains node, and her conditional weight
        stack.push((level_nodes[0].clone(), 1));
        for (sk, node) in level_secrets.iter().zip(level_nodes).skip(1) {
            let mut right_node = node;
            let mut rith_secret = *sk;
            let mut right_weight = 1;

            while let Some((left_node, left_weight)) = stack.pop() {
                if left_weight != right_weight {
                    // return the node bask and wait for it to be the same weight
                    stack.push((left_node, left_weight));
                    break;
                }

                let ark_common_secret =
                    iota_function(&left_node.get_public_key().mul(rith_secret).into_affine())?;
                rith_secret = ark_common_secret;
                last_secret = ark_common_secret;

                right_node = Box::new(ARTNode::new_internal_node(
                    generator.mul(&ark_common_secret).into_affine(),
                    left_node,
                    right_node,
                ));
                right_weight += left_weight;
            }

            // put the node to the end of stack
            stack.push((right_node, right_weight));
        }

        let (root, _) = stack.pop().ok_or(ARTError::ARTLogicError)?;

        Ok((root, last_secret))
    }

    pub fn fit_leaves_in_one_level(
        mut level_nodes: Vec<ARTNode<G>>,
        mut level_secrets: Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<ArtLevel<G>, ARTError> {
        let mut level_size = 2;
        while level_size < level_nodes.len() {
            level_size <<= 1;
        }

        if level_size == level_nodes.len() {
            return Ok((level_nodes, level_secrets));
        }

        let excess = level_size - level_nodes.len();

        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();
        for _ in 0..(level_nodes.len() - excess) >> 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let ark_common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

            let node = ARTNode::new_internal_node(
                generator.mul(&ark_common_secret).into_affine(),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
            upper_level_secrets.push(ark_common_secret);
        }

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        if secrets.is_empty() {
            return Err(ARTError::InvalidInput);
        }
        let mut level_nodes = Vec::with_capacity(secrets.len());
        let mut level_secrets = Vec::with_capacity(secrets.len());

        // Process leaves of the tree
        for leaf_secret in secrets {
            let node = ARTNode::new_leaf(generator.mul(leaf_secret).into_affine());

            level_nodes.push(node);
            level_secrets.push(*leaf_secret);
        }

        // fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets, generator)?;
        }

        let mut level_boxes = Vec::new();
        for node in level_nodes {
            level_boxes.push(Box::new(node));
        }

        let (root, tk) =
            Self::compute_next_layer_of_tree(level_boxes, &mut level_secrets, generator)?;

        let root_key = ARTRootKey {
            key: tk,
            generator: *generator,
        };

        let art = Self {
            root,
            generator: *generator,
        };

        Ok((art, root_key))
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(self).map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(ARTError::Postcard)
    }
}

impl<G> PublicART<G>
where
    // Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub fn get_path_to_leaf(&self, public_key: &G) -> Result<Vec<Direction>, ARTError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(public_key) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        Err(ARTError::PathNotExists)
    }

    pub fn get_node_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.get_public_key().eq(public_key) {
                return Ok(node);
            }
        }

        Err(ARTError::PathNotExists)
    }

    pub fn get_mut_node_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.get_public_key().eq(public_key) {
                let path = path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>();

                return self.get_mut_node(&NodeIndex::Direction(path));
            }
        }

        Err(ARTError::PathNotExists)
    }

    pub fn get_leaf_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(public_key) {
                return Ok(node);
            }
        }

        Err(ARTError::PathNotExists)
    }

    pub fn get_mut_leaf_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(public_key) {
                let path = path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>();

                return self.get_mut_node(&NodeIndex::Direction(path));
            }
        }

        Err(ARTError::PathNotExists)
    }

    pub fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: &NodeIndex,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError> {
        let co_path_values = self.get_co_path_values(node_index)?;

        let mut ark_secret = secret_key;
        let mut secrets: Vec<G::ScalarField> = vec![secret_key];
        let mut path_values: Vec<G> = vec![G::generator().mul(ark_secret).into_affine()];
        for public_key in co_path_values.iter() {
            ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
            secrets.push(ark_secret);
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

    pub fn compute_artefacts_for_verification(
        &self,
        changes: &BranchChanges<G>,
    ) -> Result<VerifierArtefacts<G>, ARTError> {
        let mut co_path = Vec::new();

        let mut parent = self.get_root();
        for direction in &changes.node_index.get_path()? {
            if parent.is_leaf() {
                if let BranchChangesType::AppendNode = changes.change_type
                    && parent.is_active()
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.get_public_key())
                }
            } else {
                co_path.push(parent.get_other_child(direction)?.get_public_key());
                parent = parent.get_child(direction)?;
            }
        }

        co_path.reverse();

        Ok(VerifierArtefacts {
            path: changes.public_keys.iter().rev().cloned().collect(),
            co_path,
        })
    }

    pub fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.get_generator().mul(secret).into_affine()
    }

    pub fn append_or_replace_node_in_public_art(
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

    pub fn make_blank_in_public_art(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let append_changes = matches!(
            self.get_node(&NodeIndex::from(path.to_vec()))?.get_status(),
            Some(LeafStatus::Blank)
        );
        let update_weights = !append_changes;

        self.make_blank_without_changes_with_options(path, update_weights)?;

        self.update_art_branch_with_leaf_secret_key(temporary_secret_key, path, append_changes)
            .map(|(root_key, mut changes, artefacts)| {
                changes.change_type = BranchChangesType::MakeBlank;
                (root_key, changes, artefacts)
            })
    }

    pub fn update_art_with_changes(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        if changes.public_keys.is_empty() {
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

    pub fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError> {
        self.get_node_with_path(&index.get_path()?)
    }

    pub fn get_node_with_path(&self, path: &[Direction]) -> Result<&ARTNode<G>, ARTError> {
        let mut node = self.get_root();
        for direction in path {
            node = node.get_child(direction)?;
        }

        Ok(node)
    }

    pub fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError> {
        self.get_mut_node_with_path(&index.get_path()?)
    }

    pub fn get_mut_node_with_path(
        &mut self,
        path: &[Direction],
    ) -> Result<&mut ARTNode<G>, ARTError> {
        let mut node = self.get_mut_root();
        for direction in path {
            node = node.get_mut_child(direction)?;
        }

        Ok(node)
    }

    pub fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && matches!(
                self.get_node(&changes.node_index)?.get_status(),
                Some(LeafStatus::Blank)
            )
        {
            self.update_public_art_with_options(changes, true, false)
        } else {
            self.update_public_art_with_options(changes, false, true)
        }
    }

    pub fn update_public_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKey => {}
            BranchChangesType::AppendNode => {
                let leaf =
                    ARTNode::new_leaf(*changes.public_keys.last().ok_or(ARTError::NoChanges)?);
                self.append_or_replace_node_without_changes(leaf, &changes.node_index.get_path()?)?;
            }
            BranchChangesType::MakeBlank => {
                self.make_blank_without_changes_with_options(
                    &changes.node_index.get_path()?,
                    update_weights,
                )?;
            }
            BranchChangesType::Leave => {
                self.get_mut_node(&changes.node_index)?
                    .set_status(LeafStatus::PendingRemoval)?;
                // let mut update_path = changes.node_index.get_path()?;
                // // update_path.pop();
                // self.update_weights(&update_path, false)?;
            }
        }

        self.update_art_with_changes(changes, append_changes)
    }

    pub fn merge_all(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError> {
        self.merge_with_skip(&[], target_changes)
    }

    pub fn merge_with_skip(
        &mut self,
        applied_changes: &[BranchChanges<G>],
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError> {
        for change in applied_changes {
            match change.change_type {
                BranchChangesType::UpdateKey | BranchChangesType::MakeBlank => {}
                _ => return Err(ARTError::InvalidInput),
            }
        }

        let mut key_update_changes = Vec::new();
        let mut make_blank_changes = Vec::new();
        let mut append_member_changes = Vec::new();

        for change in target_changes {
            match change.change_type {
                BranchChangesType::UpdateKey => {
                    key_update_changes.push(change.clone());
                }
                BranchChangesType::Leave => {
                    key_update_changes.push(change.clone());
                }
                BranchChangesType::MakeBlank => {
                    make_blank_changes.push(change.clone());
                }
                BranchChangesType::AppendNode => {
                    append_member_changes.push(change.clone());
                }
            }
        }

        // merge all key update changes but skip whose from applied_changes
        let mut iteration_start = applied_changes.len();
        let mut changes = applied_changes.to_vec();
        let key_update_changes_len = key_update_changes.len();

        let mut previous_shift = key_update_changes.len();
        changes.extend(key_update_changes);
        for i in iteration_start..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }
        iteration_start += previous_shift;

        previous_shift = make_blank_changes.len();
        changes.extend(make_blank_changes);
        for i in iteration_start..changes.len() {
            // Make blank changes are of replaces all public keys on path or appends to all of them.
            if key_update_changes_len == 0 && self.get_node(&changes[i].node_index)?.is_active() {
                self.update_public_art_with_options(&changes[i], false, true)?;
            } else {
                self.update_public_art_with_options(&changes[i], true, false)?;
            }
        }
        iteration_start += previous_shift;

        self.prepare_structure_for_append_node_changes(&*append_member_changes)?;
        changes.extend(append_member_changes);
        for i in iteration_start..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }

        Ok(())
    }
}

impl<G> PublicART<G>
where
    // Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub(crate) fn get_co_path_values(&self, index: &NodeIndex) -> Result<Vec<G>, ARTError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in &index.get_path()? {
            co_path_values.push(parent.get_other_child(direction)?.get_public_key());
            parent = parent.get_child(direction)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    pub(crate) fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in LeafIterWithPath::new(self.get_root()) {
            if !node.is_active() {
                let mut node_path = Vec::with_capacity(path.len());

                for (_, dir) in path {
                    node_path.push(dir);
                }

                return Some(node_path);
            }
        }

        None
    }

    pub(crate) fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ARTError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate.get_left()?;
            let r = candidate.get_right()?;

            match l.get_weight() <= r.get_weight() {
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

    pub(crate) fn append_or_replace_node_without_changes(
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

            *node_for_extension.get_mut_weight()? += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension.get_mut_child(direction)?;
        }
        let next_node_direction = node_for_extension.is_active();
        node_for_extension.extend_or_replace(node)?;

        Ok(next_node_direction)
    }

    pub(crate) fn make_blank_without_changes_with_options(
        &mut self,
        path: &[Direction],
        update_weights: bool,
    ) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            if update_weights {
                *target_node.get_mut_weight()? -= 1;
            }
            target_node = target_node.get_mut_child(direction)?;
        }

        target_node.set_status(LeafStatus::Blank)?;

        Ok(())
    }

    pub(crate) fn update_art_branch_with_leaf_secret_key(
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
            let other_child_public_key = parent.get_other_child(&next_child)?.get_public_key();

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
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(path)?),
        };

        Ok((key, changes, artefacts))
    }

    pub(crate) fn prepare_structure_for_append_node_changes(
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
                        false => a.x().cmp(&b.x()),
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

    pub(crate) fn merge_change(
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
            if let BranchChangesType::AppendNode = target_change.change_type
                && level < target_path.len()
            {
                *node.get_mut_weight()? += 1;
                // The last node weight will be computed when the structure is updated
            }

            if shared_paths.is_empty() {
                // There are no further conflicts so change public key
                node.set_public_key(target_change.public_keys[level]);
            } else {
                // Resolve conflict by adding public keys
                node.set_public_key(
                    node.get_public_key()
                        .add(target_change.public_keys[level])
                        .into_affine(),
                );
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

    pub(crate) fn update_branch_weight(
        &mut self,
        path: &[Direction],
        increment_weight: bool,
    ) -> Result<(), ARTError> {
        for i in 0..path.len() {
            let weight = self.get_mut_node_with_path(&path[0..i])?.get_mut_weight()?;

            if increment_weight {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }

        Ok(())
    }

    pub(crate) fn get_last_public_key_on_path(
        &self,
        aggregation: &ChangeAggregationNode<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ARTError> {
        let mut leaf_public_key = self.get_root().get_public_key();

        let mut current_art_node = Some(self.get_root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            // Retrieve leaf public key from art
            if let Some(art_node) = current_art_node {
                if let Ok(node) = art_node.get_child(dir) {
                    if let ARTNode::Leaf { public_key, .. } = node {
                        leaf_public_key = *public_key;
                    }

                    current_art_node = Some(node);
                } else {
                    current_art_node = None;
                }
            }

            // Retrieve leaf public key updates form aggregation
            if let Some(agg_node) = current_agg_node {
                if let Some(node) = agg_node.get_child(*dir) {
                    for change_type in &node.data.change_type {
                        match change_type {
                            BranchChangesTypeHint::MakeBlank { pk: blank_pk, .. } => {
                                leaf_public_key = *blank_pk
                            }
                            BranchChangesTypeHint::AppendNode { pk, ext_pk, .. } => {
                                if let Some(replacement_pk) = ext_pk {
                                    match path.get(i + 1) {
                                        Some(Direction::Right) => leaf_public_key = *pk,
                                        Some(Direction::Left) => {}
                                        None => leaf_public_key = *replacement_pk,
                                    }
                                } else {
                                    leaf_public_key = *pk;
                                }
                            }
                            BranchChangesTypeHint::UpdateKey { pk } => leaf_public_key = *pk,
                            BranchChangesTypeHint::Leave { pk } => leaf_public_key = *pk,
                        }
                    }

                    current_agg_node = Some(node);
                } else {
                    current_agg_node = None;
                }
            }

            // current_agg_node = current_agg_node.children.get_child(*dir).ok_or(ARTError::NoChanges)?;
        }

        Ok(leaf_public_key)
    }
}

// impl<G> ARTPublicView<G> for PublicART<G>
impl<G> PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub fn get_root(&self) -> &ARTNode<G> {
        &self.root
    }

    pub fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>> {
        &mut self.root
    }

    pub fn get_generator(&self) -> G {
        self.generator
    }

    pub fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>> {
        mem::replace(&mut self.root, new_root)
    }
}

impl<G> From<PrivateART<G>> for PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn from(mut other: PrivateART<G>) -> Self {
        let root = other.replace_root(Box::new(ARTNode::default()));

        Self {
            root,
            generator: other.get_generator(),
        }
    }
}
