use crate::art::artefacts::VerifierArtefacts;
use crate::art::{ArtLevel, ArtUpdateOutput, ProverArtefacts};
use crate::art_node::{ArtNode, LeafIterWithPath, LeafStatus, TreeMethods};
use crate::changes::aggregations::AggregationNode;
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem;

/// Standard ART tree with public keys.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct PublicArt<G>
where
    G: AffineRepr,
{
    pub(crate) tree_root: ArtNode<G>,
}

/// ART structure, which stores and operates with some user secrets. Wrapped around `PublicArt`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct PrivateArt<G>
where
    G: AffineRepr,
{
    /// Public part of the art
    pub(crate) public_art: PublicArt<G>,

    /// Set of secret keys on path from the user leaf to the root.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) secrets: Vec<G::ScalarField>,

    /// Index of a user leaf.
    pub(crate) node_index: NodeIndex,
}

impl<G> PublicArt<G>
where
    G: AffineRepr,
{
    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn get_co_path_values(&self, path: &[Direction]) -> Result<Vec<G>, ArtError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in path {
            co_path_values.push(
                parent
                    .get_child(direction.other())
                    .ok_or(ArtError::InvalidInput)?
                    .get_public_key(),
            );
            parent = parent
                .get_child(*direction)
                .ok_or(ArtError::PathNotExists)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    /// Updates art with given changes. Available options are:
    /// - `append_changes` - if false replace public keys with provided in changes, Else, append
    ///   them to the available ones.
    /// - `update_weights` - If true updates the weights of the art on make blank change. If
    ///   false, it will leve those weights as is. Can be used to correctly apply the second
    ///   blanking of some node.
    pub(crate) fn update_with_options(
        &mut self,
        change: &BranchChange<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ArtError> {
        match &change.change_type {
            BranchChangeType::UpdateKey => {}
            BranchChangeType::AddMember => {
                let leaf =
                    ArtNode::new_leaf(*change.public_keys.last().ok_or(ArtError::NoChanges)?);
                self.append_or_replace_node_without_changes(leaf, &change.node_index.get_path()?)?;
            }
            BranchChangeType::RemoveMember => {
                self.make_blank_without_changes_with_options(
                    &change.node_index.get_path()?,
                    update_weights,
                )?;
            }
            BranchChangeType::Leave => {
                self.get_mut_node(&change.node_index)?
                    .set_status(LeafStatus::PendingRemoval)?;
            }
        }

        self.update_art_with_changes(change, append_changes)
    }

    /// Extends or replaces a leaf on the end of a given path with the given node. This method
    /// doesn't change other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc. The return value is true if the target node is extended
    /// with the other. Else it will be replaced.
    pub(crate) fn append_or_replace_node_without_changes(
        &mut self,
        node: ArtNode<G>,
        path: &[Direction],
    ) -> Result<bool, ArtError> {
        let mut node_for_extension = self.get_mut_root();
        for direction in path {
            if node_for_extension.is_leaf() {
                // The last node weight is done automatically through the extension method in ArtNode
                break;
            }

            *node_for_extension.get_mut_weight()? += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension
                .get_mut_child(*direction)
                .ok_or(ArtError::InvalidInput)?;
        }
        let perform_extension = matches!(node_for_extension.get_status(), Some(LeafStatus::Active));
        node_for_extension.extend_or_replace(node)?;

        Ok(perform_extension)
    }

    /// Converts the type of leaf on a given path to blank leaf by changing its public key on a temporary one.
    /// This method doesn't change other art nodes. To update art afterward, use update_art_with_secret_key
    /// or update_art_with_changes.
    pub(crate) fn make_blank_without_changes_with_options(
        &mut self,
        path: &[Direction],
        update_weights: bool,
    ) -> Result<(), ArtError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            if update_weights {
                *target_node.get_mut_weight()? -= 1;
            }
            target_node = target_node
                .get_mut_child(*direction)
                .ok_or(ArtError::InvalidInput)?;
        }

        target_node.set_status(LeafStatus::Blank)?;

        Ok(())
    }

    /// Updates art public keys using public keys provided in changes. It doesn't change the art
    /// structure.
    pub(crate) fn update_art_with_changes(
        &mut self,
        changes: &BranchChange<G>,
        append_changes: bool,
    ) -> Result<(), ArtError> {
        if changes.public_keys.is_empty() {
            return Err(ArtError::InvalidInput);
        }

        let mut current_node = self.get_mut_root();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key_with_options(changes.public_keys[i], append_changes);
            current_node = current_node
                .get_mut_child(
                    *changes
                        .node_index
                        .get_path()?
                        .get(i)
                        .unwrap_or(&Direction::Right),
                )
                .ok_or(ArtError::InvalidInput)?;
        }

        current_node.set_public_key_with_options(
            changes.public_keys[changes.public_keys.len() - 1],
            append_changes,
        );

        Ok(())
    }

    pub(crate) fn find_place_for_new_node(&self) -> Result<Vec<Direction>, ArtError> {
        match self.find_path_to_left_most_blank_node() {
            Some(path) => Ok(path),
            None => self.find_path_to_lowest_leaf(),
        }
    }

    /// Returns helper structure for verification of art update.
    pub(crate) fn compute_artefacts_for_verification(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<VerifierArtefacts<G>, ArtError> {
        let mut co_path = Vec::new();

        let mut parent = self.get_root();
        for direction in &changes.node_index.get_path()? {
            if parent.is_leaf() {
                if let BranchChangeType::AddMember = changes.change_type
                    && matches!(parent.get_status(), Some(LeafStatus::Active))
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.get_public_key())
                }
            } else {
                co_path.push(
                    parent
                        .get_child(direction.other())
                        .ok_or(ArtError::PathNotExists)?
                        .get_public_key(),
                );
                parent = parent
                    .get_child(*direction)
                    .ok_or(ArtError::PathNotExists)?;
            }
        }

        co_path.reverse();

        Ok(VerifierArtefacts {
            path: changes.public_keys.iter().rev().cloned().collect(),
            co_path,
        })
    }

    /// update weights on the given branch. If true increment 1, else decrement one. Ignore
    /// leaves, as their weight is automatic.
    pub(crate) fn update_weight(
        &mut self,
        path: &[Direction],
        increment: bool,
    ) -> Result<(), ArtError> {
        let mut current_node = self.get_mut_root();

        if current_node.update_weight(increment).is_err() {
            return Ok(());
        };

        for dir in path.iter() {
            current_node = current_node
                .get_mut_child(*dir)
                .ok_or(ArtError::PathNotExists)?;

            if current_node.update_weight(increment).is_err() {
                return Ok(());
            };
        }

        Ok(())
    }

    /// Updates Public keys on path utilizing the given marker tree, to decide, which nodes should be merged together.
    pub(crate) fn merge_by_marker(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
        marker_tree: &mut AggregationNode<bool>,
    ) -> Result<(), ArtError> {
        let mut parent_node = self.get_mut_root();
        let mut parent_marker_node = marker_tree;
        let mut merge_key = parent_marker_node.data;

        parent_node.set_public_key_with_options(public_keys[0], merge_key);
        parent_marker_node.data = true;

        for (dir, pk) in path.iter().zip(public_keys[1..].iter()) {
            if !merge_key {
                let neighbour_marker_node = parent_marker_node
                    .get_mut_child(dir.other())
                    .ok_or(ArtError::InvalidMarkerTree)?;
                neighbour_marker_node.data = false;
            }

            let child_node = parent_node
                .get_mut_child(*dir)
                .ok_or(ArtError::PathNotExists)?;
            let child_marker_node = parent_marker_node
                .get_mut_child(*dir)
                .ok_or(ArtError::InvalidMarkerTree)?;

            child_node.set_public_key_with_options(*pk, child_marker_node.data && merge_key);
            if !child_marker_node.data {
                merge_key = false;
            }

            child_marker_node.data = true;

            parent_node = child_node;
            parent_marker_node = child_marker_node;
        }

        Ok(())
    }

    /// Updates Public keys on path utilizing the given marker tree, to decide, which nodes should be merged together.
    pub(crate) fn apply_as_merge_conflict(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
    ) -> Result<(), ArtError> {
        let mut parent_node = self.get_mut_root();
        parent_node.set_public_key_with_options(public_keys[0], true);

        for (dir, pk) in path.iter().zip(public_keys[1..].iter()) {
            parent_node = parent_node
                .get_mut_child(*dir)
                .ok_or(ArtError::PathNotExists)?;
            parent_node.set_public_key_with_options(*pk, true);
        }

        Ok(())
    }

    /// Searches for the left most blank node and returns the vector of directions to it.
    fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in LeafIterWithPath::new(self.get_root()) {
            if node.is_leaf() && !matches!(node.get_status(), Some(LeafStatus::Active)) {
                let mut node_path = Vec::with_capacity(path.len());

                for (_, dir) in path {
                    node_path.push(dir);
                }

                return Some(node_path);
            }
        }

        None
    }

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left branch.
    fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ArtError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate
                .get_child(Direction::Left)
                .ok_or(ArtError::PathNotExists)?;
            let r = candidate
                .get_child(Direction::Right)
                .ok_or(ArtError::PathNotExists)?;

            let next_direction = match l.get_weight() <= r.get_weight() {
                true => Direction::Left,
                false => Direction::Right,
            };

            next.push(next_direction);
            candidate = candidate
                .get_child(next_direction)
                .ok_or(ArtError::InvalidInput)?;
        }

        while let ArtNode::Internal { l, r, .. } = candidate {
            if l.get_weight() <= r.get_weight() {
                next.push(Direction::Left);
                candidate = l;
            } else {
                next.push(Direction::Right);
                candidate = r;
            }
        }

        Ok(next)
    }
}

impl<G> PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn setup(secrets: &[G::ScalarField]) -> Result<Self, ArtError> {
        if secrets.is_empty() {
            return Err(ArtError::InvalidInput);
        }

        let mut level_nodes = Vec::with_capacity(secrets.len());
        let mut level_secrets = secrets.to_vec();

        // Process leaves of the tree
        for leaf_secret in secrets {
            level_nodes.push(Box::new(ArtNode::new_leaf(
                G::generator().mul(leaf_secret).into_affine(),
            )));
        }

        // Fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets)?;
        }

        let (root, _) = Self::compute_root_node_from_leaves(level_nodes, &mut level_secrets)?;

        let public_art = PublicArt {
            tree_root: root.as_ref().to_owned(),
        };

        let sk = *secrets.first().ok_or(ArtError::EmptyArt)?;
        let pk = G::generator().mul(sk).into_affine();
        let path = public_art.get_path_to_leaf_with(pk)?;
        let co_path = public_art.get_co_path_values(&path)?;
        let artefacts = recompute_artefacts(sk, &co_path)?;

        Ok(Self {
            public_art,
            secrets: artefacts.secrets,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn new(public_art: PublicArt<G>, secret_key: G::ScalarField) -> Result<Self, ArtError> {
        let leaf_path =
            public_art.get_path_to_leaf_with(G::generator().mul(secret_key).into_affine())?;
        let co_path = public_art.get_co_path_values(&leaf_path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;

        Ok(Self {
            public_art,
            secrets: artefacts.secrets,
            node_index: NodeIndex::from(leaf_path).as_index()?,
        })
    }

    pub fn restore(
        public_art: PublicArt<G>,
        secrets: Vec<G::ScalarField>,
    ) -> Result<Self, ArtError> {
        let pk = G::generator()
            .mul(secrets.first().ok_or(ArtError::EmptyArt)?)
            .into_affine();
        let path = public_art.get_path_to_leaf_with(pk)?;
        Ok(Self {
            public_art,
            secrets,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    pub fn get_leaf_secret_key(&self) -> G::ScalarField {
        self.secrets[0]
    }

    pub fn get_root_secret_key(&self) -> G::ScalarField {
        self.secrets[self.secrets.len() - 1]
    }

    pub fn get_secrets(&self) -> &Vec<G::ScalarField> {
        &self.secrets
    }

    pub fn get_leaf_public_key(&self) -> G {
        G::generator().mul(self.get_leaf_secret_key()).into_affine()
    }

    pub fn get_root_public_key(&self) -> G {
        G::generator().mul(self.get_root_secret_key()).into_affine()
    }

    pub fn get_public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    pub(crate) fn ephemeral_update_art_branch_with_leaf_secret_key(
        &mut self,
        secret_key: G::ScalarField,
        path: &[Direction],
    ) -> Result<ArtUpdateOutput<G>, ArtError> {
        let co_path = self.public_art.get_co_path_values(path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;

        let changes = BranchChange {
            change_type: BranchChangeType::UpdateKey,
            public_keys: artefacts.path.iter().rev().cloned().collect(),
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(path)?),
        };

        Ok((
            artefacts.secrets[artefacts.secrets.len() - 1],
            changes,
            artefacts,
        ))
    }

    /// This method will update all public keys on a path from the root to node. Using provided
    /// secret key, it will recompute all the public keys and change old ones. It is used
    /// internally in algorithms for art updateCan be used to update art after applied changes.
    pub(crate) fn update_art_branch_with_leaf_secret_key(
        &mut self,
        secret_key: G::ScalarField,
        path: &[Direction],
        append_changes: bool,
    ) -> Result<ArtUpdateOutput<G>, ArtError> {
        let co_path = self.public_art.get_co_path_values(path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;
        let tk = *artefacts.secrets.last().ok_or(ArtError::EmptyArt)?;
        let change = artefacts.derive_branch_change(
            BranchChangeType::UpdateKey,
            NodeIndex::from(path.to_vec()).as_index()?,
        )?;

        self.public_art.update_art_with_changes(&change, append_changes)?;

        Ok((tk, change, artefacts))
    }

    /// Ok if change can be applied to the ART tree. Else Err.
    pub(crate) fn verify_change_applicability(
        &self,
        change: &BranchChange<G>,
    ) -> Result<(), ArtError> {
        if self.get_node_index().is_subpath_of(&change.node_index)? {
            match change.change_type {
                BranchChangeType::RemoveMember => return Err(ArtError::InapplicableBlanking),
                BranchChangeType::UpdateKey => return Err(ArtError::InapplicableKeyUpdate),
                BranchChangeType::Leave => return Err(ArtError::InapplicableLeave),
                BranchChangeType::AddMember => {}
            }
        }

        Ok(())
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub(crate) fn update_private_art_with_options(
        &mut self,
        change: &BranchChange<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ArtError> {
        // If your node is to be blanked, return error, as it is impossible to update
        // path secrets at that point.
        if self.get_node_index().is_subpath_of(&change.node_index)? {
            match change.change_type {
                BranchChangeType::RemoveMember => return Err(ArtError::InapplicableBlanking),
                BranchChangeType::UpdateKey => return Err(ArtError::InapplicableKeyUpdate),
                BranchChangeType::Leave => return Err(ArtError::InapplicableLeave),
                BranchChangeType::AddMember => {
                    // Extend path_secrets. Append additional leaf secret to the start.
                    let mut new_path_secrets =
                        vec![*self.secrets.first().ok_or(ArtError::EmptyArt)?];
                    new_path_secrets.append(self.secrets.clone().as_mut());
                    self.secrets = new_path_secrets;
                }
            }
        }

        self.public_art
            .update_with_options(change, append_changes, update_weights)?;

        if let BranchChangeType::AddMember = &change.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(change)?;

        self.update_secrets_on_intersection(artefact_secrets, &change.node_index, append_changes)?;

        Ok(())
    }

    /// If `append_changes` is false, works as `set_path_secrets`. In the other case, it will
    /// append secrets to available ones. Works correctly if `self.node_index` isn't a subpath
    /// of the `other`. The `other` is used to properly decide, which secrets did change.
    pub(crate) fn update_secrets_on_intersection(
        &mut self,
        other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ArtError> {
        let intersection = other.intersect_with(self.get_node_index())?;

        let start = other_path_secrets
            .len()
            .saturating_sub(intersection.len() + 1);

        self.update_secrets(&other_path_secrets[start..], append_changes)
    }

    /// Update upper half of secrets.
    pub(crate) fn update_secrets(
        &mut self,
        updated_secrets: &[G::ScalarField],
        merge_key: bool,
    ) -> Result<(), ArtError> {
        for (sk, i) in updated_secrets
            .iter()
            .rev()
            .zip((0..self.secrets.len()).rev())
        {
            if merge_key {
                self.secrets[i] += sk;
            } else {
                self.secrets[i] = *sk;
            }
        }

        Ok(())
    }

    /// Updates users node index by researching it in a tree.
    pub(crate) fn update_node_index(&mut self) -> Result<(), ArtError> {
        let path = self.get_path_to_leaf_with(self.get_leaf_public_key())?;
        self.node_index = NodeIndex::Direction(path).as_index()?;

        Ok(())
    }

    /// Updates users node index by researching it in a tree.
    pub(crate) fn update_node_index_and_extend_secrets(&mut self) -> Result<(), ArtError> {
        let path = self.get_path_to_leaf_with(self.get_leaf_public_key())?;
        let secrets_extension_len = path.len().saturating_sub(self.node_index.get_path()?.len());
        self.node_index = NodeIndex::Direction(path).as_index()?;

        if secrets_extension_len != 0 {
            let mut new_secrets = vec![self.get_leaf_secret_key(); secrets_extension_len];
            new_secrets.append(&mut mem::take(&mut self.secrets));
            self.secrets = new_secrets;
        }

        Ok(())
    }

    pub(crate) fn private_update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
    ) -> Result<ArtUpdateOutput<G>, ArtError> {
        let path = target_leaf.get_path()?;
        let (tk, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, append_changes)?;

        self.update_secrets_on_intersection(
            artefacts.secrets.clone(),
            &changes.node_index,
            append_changes,
        )?;

        Ok((tk, changes, artefacts))
    }

    pub(crate) fn private_add_node(
        &mut self,
        new_key: G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ArtError> {
        let mut path = self.public_art.find_place_for_new_node()?;

        let new_leaf = ArtNode::new_leaf(G::generator().mul(new_key).into_affine());
        let target_leaf = self.get_node_at(&path)?;

        if !target_leaf.is_leaf() {
            return Err(ArtError::LeafOnly);
        }

        let extend_node = matches!(target_leaf.get_status(), Some(LeafStatus::Active));

        self.public_art.update_weight(&path, true)?;
        self.get_mut_node_at(&path)?.extend_or_replace(new_leaf)?;

        if extend_node {
            path.push(Direction::Right);
        }

        let (tk, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, false)?;

        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            let mut new_path_secrets = vec![*self.secrets.first().ok_or(ArtError::EmptyArt)?];
            new_path_secrets.append(self.secrets.clone().as_mut());
            self.secrets = new_path_secrets;
        }
        self.update_node_index()?;

        self.update_secrets_on_intersection(artefacts.secrets.clone(), &changes.node_index, false)?;

        Ok((tk, changes, artefacts))
    }

    /// Computes the ART assuming that `level_nodes` and `level_secrets` are a power of two. If
    /// they are not they can be lifted with `fit_leaves_in_one_level` method.
    fn compute_root_node_from_leaves(
        level_nodes: Vec<Box<ArtNode<G>>>,
        level_secrets: &mut [G::ScalarField],
    ) -> Result<(Box<ArtNode<G>>, G::ScalarField), ArtError> {
        let mut stack = Vec::with_capacity(level_nodes.len());

        let mut last_secret = G::ScalarField::zero();

        // stack contains node, and her conditional weight
        stack.push((level_nodes[0].clone(), 1));
        for (sk, node) in level_secrets.iter().zip(level_nodes).skip(1) {
            let mut right_node = node;
            let mut right_secret = *sk;
            let mut right_weight = 1;

            while let Some((left_node, left_weight)) = stack.pop() {
                if left_weight != right_weight {
                    // return the node bask and wait for it to be the same weight
                    stack.push((left_node, left_weight));
                    break;
                }

                let ark_common_secret =
                    iota_function(&left_node.get_public_key().mul(right_secret).into_affine())?;
                right_secret = ark_common_secret;
                last_secret = ark_common_secret;

                right_node = Box::new(ArtNode::new_internal_node(
                    G::generator().mul(&ark_common_secret).into_affine(),
                    left_node,
                    right_node,
                ));
                right_weight += left_weight;
            }

            // put the node to the end of stack
            stack.push((right_node, right_weight));
        }

        let (root, _) = stack.pop().ok_or(ArtError::ArtLogic)?;

        Ok((root, last_secret))
    }

    fn fit_leaves_in_one_level(
        mut level_nodes: Vec<Box<ArtNode<G>>>,
        mut level_secrets: Vec<G::ScalarField>,
    ) -> Result<ArtLevel<G>, ArtError> {
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

            let common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

            let node = ArtNode::new_internal_node(
                G::generator().mul(&common_secret).into_affine(),
                left_node,
                right_node,
            );

            upper_level_nodes.push(Box::new(node));
            upper_level_secrets.push(common_secret);
        }

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    /// Returns secrets from changes (ordering from leaf to the root).
    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<Vec<G::ScalarField>, ArtError> {
        let intersection = self.get_node_index().intersect_with(&changes.node_index)?;

        let mut co_path = Vec::new();
        let mut current_node = self.get_root();
        for dir in &intersection {
            co_path.push(
                current_node
                    .get_child(dir.other())
                    .ok_or(ArtError::InvalidInput)?
                    .get_public_key(),
            );
            current_node = current_node.get_child(*dir).ok_or(ArtError::InvalidInput)?;
        }

        if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
            co_path.push(*public_key);
        }

        co_path.reverse();

        let secrets = self.get_partial_path_secrets(&co_path)?;

        Ok(secrets)
    }

    /// Instead of recomputing path secretes from the leaf to root, this method takes some secret
    /// key in `path_secrets`, considering previous are unchanged, and recomputes the remaining
    /// `path_secrets`, which have changed. `partial_co_path` is a co-path from some inner node to
    /// the root, required to compute secrets.
    fn get_partial_path_secrets(
        &self,
        partial_co_path: &[G],
    ) -> Result<Vec<G::ScalarField>, ArtError> {
        let path_length = self.secrets.len();
        let updated_path_len = partial_co_path.len();

        let level_sk = self.secrets[path_length - updated_path_len - 1];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, partial_co_path)?;

        let mut new_path_secrets = self.secrets.clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        Ok(new_path_secrets)
    }
}

impl<G> PartialEq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        if self.get_root() == other.get_root()
            && self.get_root_secret_key() == other.get_root_secret_key()
        {
            return true;
        }

        false
    }
}

impl<G> Eq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
}

#[cfg(test)]
mod tests {
    use crate::art::PrivateArt;
    use crate::art_node::{LeafIterWithPath, TreeMethods};
    use crate::test_helper_tools::init_tracing;
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::cmp::{max, min};

    const TEST_GROUP_SIZE: usize = 100;

    #[test]
    /// Test if art serialization -> deserialization works correctly for unchanged arts
    fn test_public_art_initial_serialization() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);

        for i in (TEST_GROUP_SIZE - 1)..TEST_GROUP_SIZE {
            let secrets = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

            let private_art = PrivateArt::setup(&secrets).unwrap();
            let public_art_bytes = to_allocvec(&private_art.get_public_art()).unwrap();

            // Try to deserialize art for every other user in a group
            for j in 0..i {
                let deserialized_art: PrivateArt<CortadoAffine> =
                    PrivateArt::new(from_bytes(&public_art_bytes).unwrap(), secrets[j]).unwrap();

                assert_eq!(
                    deserialized_art, private_art,
                    "Both users have the same view on the state of the art",
                );
            }
        }
    }

    #[test]
    fn test_art_weight_balance_at_creation() {
        for i in 1..TEST_GROUP_SIZE {
            let mut rng = StdRng::seed_from_u64(0);
            let secrets = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

            let mut min_height = u64::MAX;
            let mut max_height = u64::MIN;
            let root = art.get_root();

            for (_, path) in LeafIterWithPath::new(root) {
                min_height = min(min_height, path.len() as u64);
                max_height = max(max_height, path.len() as u64);
            }

            assert!(max_height - min_height < 2);
        }
    }
}
