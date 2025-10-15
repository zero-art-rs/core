use crate::types::{BranchChangesTypeHint, LeafStatus};
use crate::{
    errors::ARTError,
    helper_tools::iota_function,
    traits::{ARTPublicAPI, ARTPublicAPIHelper, ARTPublicView},
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
use std::collections::HashMap;
use tracing::{debug, error};
use crate::traits::{ARTPrivateAPI, ChildContainer};
use crate::types::{AggregationData, AggregationNodeIterWithPath, ChangeAggregation, VerifierAggregationData};

impl<G, A> ARTPublicAPI<G> for A
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G> + ARTPublicAPIHelper<G>,
{
    fn get_path_to_leaf(&self, public_key: &G) -> Result<Vec<Direction>, ARTError> {
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

    fn get_node_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.get_public_key().eq(public_key) {
                return Ok(node);
            }
        }

        Err(ARTError::PathNotExists)
    }

    fn get_mut_node_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError> {
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

    fn get_leaf_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(public_key) {
                return Ok(node);
            }
        }

        Err(ARTError::PathNotExists)
    }

    fn get_mut_leaf_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError> {
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

    fn recompute_root_key_with_artefacts_using_secret_key(
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

    fn compute_artefacts_for_verification(
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

    fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.get_generator().mul(secret).into_affine()
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

    fn make_blank_in_public_art(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>), ARTError> {
        let (append_changes, update_weights) =
            match !self.get_node(&NodeIndex::from(path.to_vec()))?.is_active() {
                true => (true, false),
                false => (false, true),
            };

        self.make_blank_without_changes_with_options(path, update_weights)?;

        self.update_art_branch_with_leaf_secret_key(temporary_secret_key, path, append_changes)
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

    fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError> {
        self.get_node_with_path(&index.get_path()?)
    }

    fn get_node_with_path(&self, path: &[Direction]) -> Result<&ARTNode<G>, ARTError> {
        let mut node = self.get_root();
        for direction in path {
            node = node.get_child(direction)?;
        }

        Ok(node)
    }

    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError> {
        self.get_mut_node_with_path(&index.get_path()?)
    }

    fn get_mut_node_with_path(&mut self, path: &[Direction]) -> Result<&mut ARTNode<G>, ARTError> {
        let mut node = self.get_mut_root();
        for direction in path {
            node = node.get_mut_child(direction)?;
        }

        Ok(node)
    }

    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && !self.get_node(&changes.node_index)?.is_active()
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
        }

        self.update_art_with_changes(changes, append_changes)
    }

    fn merge_all(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError> {
        self.merge_with_skip(&[], target_changes)
    }

    fn merge_with_skip(
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

    fn get_last_leaf_pk_on_path(
        &self,
        aggregation: &ChangeAggregation<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ARTError> {
        let mut leaf_public_key = self.get_root().get_public_key();

        let mut current_art_node = Some(self.get_root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            // Retrieve leaf public key from art
            if let Some(art_node) = current_art_node {
                if let Ok(node) = art_node.get_child(dir) {
                    if let ARTNode::Leaf {public_key, .. } = node {
                        leaf_public_key = *public_key;
                    }

                    current_art_node = Some(node);
                } else {
                    current_art_node = None;
                }
            }

            // Retrieve leaf public key updates form aggregation
            if let Some(agg_node) = current_agg_node {
                if let Some(node) = agg_node.children.get_child(*dir) {
                    for change_type in &node.data.change_type {
                        match change_type {
                            BranchChangesTypeHint::MakeBlank { blank_pk, .. } => leaf_public_key = *blank_pk,
                            BranchChangesTypeHint::AppendNode { pk, ext_pk, .. } => {
                                if let Some(replacement_pk) = ext_pk {
                                    match path.get(i + 1) {
                                        Some(Direction::Right) => leaf_public_key = *pk,
                                        Some(Direction::Left) => {},
                                        None => leaf_public_key = *replacement_pk,
                                    }
                                } else {
                                    leaf_public_key = *pk;
                                }
                            }
                            BranchChangesTypeHint::UpdateKey { pk } => leaf_public_key = *pk,
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

    fn get_aggregation_co_path(
        &self,
        aggregation: &ChangeAggregation<AggregationData<G>>,
    ) -> Result<ChangeAggregation<VerifierAggregationData<G>>, ARTError> {
        let mut resulting_aggregation =
            ChangeAggregation::<VerifierAggregationData<G>>::try_from(aggregation)?;

        for (_, path) in AggregationNodeIterWithPath::new(aggregation).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let last_direction = parent_path.pop().ok_or(ARTError::NoChanges)?;

            let aggregation_parent = path
                .last()
                .ok_or(ARTError::NoChanges)
                .map(|(node, _)| *node)?;

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
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                resulting_target_node.data.co_public_key = Some(self.get_last_leaf_pk_on_path(aggregation, &path)?);
            }
        }

        Ok(resulting_aggregation)
    }

    fn update_public_art_with_aggregation(
        &mut self,
        verifier_aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
    ) -> Result<(), ARTError> {
        for (item, path) in AggregationNodeIterWithPath::new(verifier_aggregation) {
            let item_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            for change_type in &item.data.change_type {
                match change_type {
                    BranchChangesTypeHint::MakeBlank { blank_pk, merge } => {
                        if !*merge {
                            self.update_branch_weight(&item_path, false)?;
                        }

                        self.update_public_art_upper_branch(
                            &item_path,
                            &verifier_aggregation,
                            false,
                            0
                        )?;

                        let corresponding_item =
                            self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.set_status(LeafStatus::Blank)?;
                        corresponding_item.set_public_key(*blank_pk);
                    }
                    BranchChangesTypeHint::AppendNode { extend, pk, ext_pk } => {
                        self.update_branch_weight(&item_path, true)?;

                        let mut parent_path = item_path.clone();
                        parent_path.pop();
                        self.update_public_art_upper_branch(
                            &parent_path,
                            &verifier_aggregation,
                            false,
                            0,
                        )?;

                        let corresponding_item =
                            self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.extend_or_replace(ARTNode::new_leaf(*pk))?;


                        if let Some(ext_pk) = ext_pk {
                            corresponding_item.set_public_key(*ext_pk)
                        }
                    }
                    BranchChangesTypeHint::UpdateKey { pk } => {
                        self.update_public_art_upper_branch(
                            &item_path,
                            &verifier_aggregation,
                            false,
                            0,
                        )?;

                        let corresponding_item = self.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.set_public_key(*pk);
                    }
                }
            }

        }
        
        Ok(())
    }
}

impl<G, A> ARTPublicAPIHelper<G> for A
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
            co_path_values.push(parent.get_other_child(direction)?.get_public_key());
            parent = parent.get_child(direction)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
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

    fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ARTError> {
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

            *node_for_extension.get_mut_weight()? += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension.get_mut_child(direction)?;
        }
        let next_node_direction = node_for_extension.is_active();
        node_for_extension.extend_or_replace(node)?;

        Ok(next_node_direction)
    }

    fn make_blank_without_changes_with_options(
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

    fn update_public_art_upper_branch(
        &mut self,
        path: &[Direction],
        verifier_aggregation: &ChangeAggregation<VerifierAggregationData<G>>,
        append_changes: bool,
        skip: usize,
    ) -> Result<(), ARTError> {
        // Update root
        let mut current_agg_node = verifier_aggregation;
        if skip == 0 {
            match append_changes {
                true => self.get_mut_root().merge_public_key(current_agg_node.data.public_key),
                false => self.get_mut_root().set_public_key(current_agg_node.data.public_key),
            }
        }


        for i in 1..skip {
            current_agg_node = current_agg_node.children.get_child(path[i]).ok_or(ARTError::InvalidAggregation)?;
        }

        for i in skip..path.len() {
            current_agg_node = current_agg_node.children.get_child(path[i + skip]).ok_or(ARTError::InvalidAggregation)?;
            let target_node = self.get_mut_node_with_path(&path[0..i + 1])?;

            match append_changes {
                true => target_node.merge_public_key(current_agg_node.data.public_key),
                false => target_node.set_public_key(current_agg_node.data.public_key),
            }
        }

        Ok(())
    }

    fn update_branch_weight(
        &mut self,
        path: &[Direction],
        increment_weight: bool,
    ) -> Result<(), ARTError> {
        for i in 0..path.len() {
            let partial_path = path[0..i].to_vec();
            let weight = self.get_mut_node(&NodeIndex::Direction(partial_path))?
                .get_mut_weight()?;

            if increment_weight {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }

        Ok(())
    }
}
