use crate::art::artefacts::VerifierArtefacts;
use crate::art::{AggregationContext, PrivateArt};
use crate::art_node::{
    ArtNode, ArtNodeData, ArtNodePreview, BinaryTree, BinaryTreeNode, LeafStatus, NodeIterWithPath,
    TreeMethods,
};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregatedChange, AggregationData, PrivateAggregatedChange, VerifierAggregationData,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::fmt::Debug;
use std::mem;
use zrt_zk::aggregated_art::VerifierAggregationTree;
use zrt_zk::art::VerifierNodeData;

/// Describes public key state after commit.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
pub struct PublicMergeData<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub strong_key: Option<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub weak_key: Option<G>,
    pub status: Option<LeafStatus>,
    pub weight_change: i32,
}

impl<G> PublicMergeData<G>
where
    G: AffineRepr,
{
    pub fn new(
        strong_key: Option<G>,
        weak_key: Option<G>,
        status: Option<LeafStatus>,
        weight_change: i32,
    ) -> Self {
        Self {
            weak_key,
            strong_key,
            status,
            weight_change,
        }
    }

    /// If `increment` is true, increment `self.weight_change`, else decrement it.
    pub fn update_weight_change(&mut self, increment: bool) {
        if increment {
            self.weight_change += 1;
        } else {
            self.weight_change -= 1;
        }
    }

    /// Change `status` to the given one. Note, that `Blank` node stays `Blank`, `PendingRemoval`
    /// can be changed to `Blank` or stay `PendingRemoval`, while `Active` node can change to any status.
    pub fn update_status(&mut self, status: LeafStatus) {
        if let Some(inner_status) = &mut self.status {
            *inner_status = max(status, *inner_status);
        } else {
            self.status = Some(status);
        }
    }

    /// Update public key of the merge data in correspondence to rules.
    pub fn update_public_key(&mut self, public_key: G, weak_only: bool) {
        if weak_only || self.strong_key.is_some() {
            match self.weak_key {
                None => self.weak_key = Some(public_key),
                Some(current_weak_key) => {
                    self.weak_key = Some((current_weak_key + public_key).into_affine())
                }
            }
        } else {
            self.strong_key = Some(public_key)
        }
    }
}

/// Standard ART tree with public keys.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct PublicArt<G>
where
    G: AffineRepr,
{
    pub(crate) tree_root: ArtNode<G>,
    pub(crate) merge_tree: BinaryTree<PublicMergeData<G>>,
}

/// The state of uncommited part of `PublicArt` tree.
pub struct PublicArtApplySnapshot<G: AffineRepr>(BinaryTree<PublicMergeData<G>>);

/// A view of the `PublicArt` state after commit.
pub struct PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    public_art: &'a PublicArt<G>,
}

impl<G> From<ArtNode<G>> for PublicArt<G>
where
    G: AffineRepr,
{
    fn from(tree_root: ArtNode<G>) -> Self {
        Self {
            tree_root,
            merge_tree: Default::default(),
        }
    }
}

impl<G: AffineRepr> PublicArtApplySnapshot<G> {
    pub fn new(merge_tree: BinaryTree<PublicMergeData<G>>) -> Self {
        Self(merge_tree)
    }
}

impl<G> PublicArt<G>
where
    G: AffineRepr,
{
    pub fn apply<C, R>(&mut self, change: &C) -> Result<R, ArtError>
    where
        C: ApplicableChange<Self, R>,
    {
        change.apply(self)
    }

    /// Returns helper data with current merge configuration. Can be used to revert change
    /// applications after last `commit()`.
    pub fn snapshot(&self) -> PublicArtApplySnapshot<G> {
        PublicArtApplySnapshot::new(self.merge_tree.clone())
    }

    /// Return merge configuration fo the state specified in provided `snapshot`.
    pub fn undo_apply(&mut self, snapshot: PublicArtApplySnapshot<G>) {
        self.merge_tree = snapshot.0;
    }

    /// Update art with all the stored epoch changes. removes all the merge data.
    pub fn commit(&mut self) -> Result<(), ArtError> {
        let Some(merge_tree) = mem::take(&mut self.merge_tree.root) else {
            return Ok(());
        };

        let art_reserve_copy = self.tree_root.clone();

        self.inner_commit(&merge_tree).inspect_err(|_| {
            self.merge_tree.root = Some(merge_tree);
            self.tree_root = art_reserve_copy;
        })
    }

    /// Clears current merge state without commiting.
    pub fn discard(&mut self) {
        self.merge_tree = Default::default();
    }

    fn inner_commit(
        &mut self,
        merge_tree: &BinaryTreeNode<PublicMergeData<G>>,
    ) -> Result<(), ArtError> {
        for (merge_node, path_data) in merge_tree.node_iter_with_path() {
            let path = path_data.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let art_node = self.mut_root().mut_node_at(&path)?;

            if art_node.is_leaf() && !merge_node.is_leaf() {
                let public_key = merge_node
                    .child(Direction::Right)
                    .ok_or(ArtError::InvalidBranchChange)?
                    .preview_public_key();
                let leaf_data = ArtNodeData::new_leaf(public_key, LeafStatus::Active, vec![]);
                art_node.extend(ArtNode::new_leaf(leaf_data));
                art_node.commit(Some(&merge_node.data))?;
            } else {
                art_node.commit(Some(&merge_node.data))?;
            }
        }

        Ok(())
    }

    pub fn find(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in self.root().node_iter_with_path() {
            if node.data().public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn find_leaf(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in self.root().node_iter_with_path() {
            if node.is_leaf() && node.data().public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn node(&self, index: &NodeIndex) -> Result<&ArtNode<G>, ArtError> {
        self.root().node(&index)
    }

    pub fn root(&self) -> &ArtNode<G> {
        &self.tree_root
    }

    pub(crate) fn mut_root(&mut self) -> &mut ArtNode<G> {
        &mut self.tree_root
    }

    pub fn preview(&'_ self) -> PublicArtPreview<'_, G> {
        PublicArtPreview { public_art: self }
    }

    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn co_path(&self, path: &[Direction]) -> Result<Vec<G>, ArtError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.root();
        for direction in path {
            co_path_values.push(
                parent
                    .child(direction.other())
                    .ok_or(ArtError::PathNotExists)?
                    .data()
                    .public_key(),
            );
            parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    pub(crate) fn apply_update_key(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
    ) -> Result<(), ArtError> {
        let merge_leaf = self
            .merge_tree
            .add_branch_keys(public_keys, path, false, None)?;

        if merge_leaf.is_leaf() {
            merge_leaf.data.update_status(LeafStatus::Active);
        } else {
            return Err(ArtError::LeafOnly);
        }

        Ok(())
    }

    pub(crate) fn apply_add_member(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
        extend_tree: bool,
    ) -> Result<(), ArtError> {
        if extend_tree {
            let new_leaf_public_key = *public_keys.last().ok_or(ArtError::NoChanges)?;

            let target_node = self.node_at(path)?;
            let public_key = target_node.data().public_key();
            let Some(status) = target_node.data().status() else {
                return Err(ArtError::InvalidBranchChange);
            };

            let merge_leaf = self.merge_tree.add_branch_keys(
                &public_keys[..public_keys.len() - 1],
                path,
                false,
                Some(true),
            )?;

            *merge_leaf.mut_child(Direction::Right) = Some(Box::new(BinaryTreeNode::new_leaf(
                PublicMergeData::new(Some(new_leaf_public_key), None, Some(LeafStatus::Active), 0),
            )));
            *merge_leaf.mut_child(Direction::Left) = Some(Box::new(BinaryTreeNode::new_leaf(
                PublicMergeData::new(Some(public_key), None, Some(status), 0),
            )));
        } else {
            let merge_leaf =
                self.merge_tree
                    .add_branch_keys(&public_keys, path, false, Some(true))?;
            merge_leaf.data.update_status(LeafStatus::Active);
        }

        Ok(())
    }

    pub(crate) fn apply_remove_member(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
        weak_only: bool,
    ) -> Result<(), ArtError> {
        let weight_change = if weak_only { None } else { Some(false) };
        let merge_leaf =
            self.merge_tree
                .add_branch_keys(public_keys, path, weak_only, weight_change)?;

        if merge_leaf.is_leaf() {
            merge_leaf.data.update_status(LeafStatus::Blank);
        } else {
            return Err(ArtError::LeafOnly);
        }

        Ok(())
    }

    pub(crate) fn apply_leave(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
    ) -> Result<(), ArtError> {
        let merge_leaf = self
            .merge_tree
            .add_branch_keys(public_keys, path, false, Some(false))?;

        if merge_leaf.is_leaf() {
            merge_leaf.data.update_status(LeafStatus::PendingRemoval);
        } else {
            return Err(ArtError::LeafOnly);
        }

        Ok(())
    }

    /// Returns helper structure for verification of art update.
    pub fn verification_branch(
        &self,
        change: &BranchChange<G>,
    ) -> Result<Vec<VerifierNodeData<G>>, ArtError> {
        let mut path = change.node_index.get_path()?;
        if matches!(change.change_type, BranchChangeType::AddMember)
            && matches!(
                self.node_at(&path)?.data().status(),
                Some(LeafStatus::Active | LeafStatus::PendingRemoval)
            )
        {
            path.push(Direction::Right);
        }

        let mut co_path = Vec::new();
        let mut parent = self.root();
        for direction in &path {
            if parent.is_leaf() {
                if let BranchChangeType::AddMember = change.change_type
                    && matches!(parent.data().status(), Some(LeafStatus::Active))
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.data().public_key())
                }
            } else {
                co_path.push(
                    parent
                        .child(direction.other())
                        .ok_or(ArtError::PathNotExists)?
                        .data()
                        .public_key(),
                );
                parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
            }
        }

        co_path.reverse();

        let verifier_artefacts = VerifierArtefacts {
            path: change.public_keys.iter().rev().cloned().collect(),
            co_path,
        };

        verifier_artefacts.to_verifier_branch()
    }

    /// Update public art public keys with ones provided in the `verifier_aggregation` tree.
    pub fn verification_tree(
        &self,
        agg: &BinaryTree<AggregationData<G>>,
    ) -> Result<VerifierAggregationTree<G>, ArtError> {
        let agg_root = match agg.root() {
            Some(root) => root,
            None => return Err(ArtError::NoChanges),
        };

        let mut resulting_aggregation_root =
            BinaryTreeNode::<VerifierAggregationData<G>>::try_from(agg_root)?;

        for (_, path) in NodeIterWithPath::new(agg_root).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let resulting_target_node = resulting_aggregation_root.mut_node_at(&parent_path)?;
            let aggregation_parent = path
                .last()
                .ok_or(ArtError::NoChanges)
                .map(|(node, _)| *node)?;

            let last_direction = parent_path.pop().ok_or(ArtError::NoChanges)?;

            // Update co-path
            let pk = if let Ok(co_leaf) = aggregation_parent.node_at(&[last_direction.other()]) {
                // Retrieve co-path from the aggregation
                co_leaf.data.public_key
            } else if let Ok(parent) = self.node_at(&parent_path)
                && let Some(other_child) = parent.child(last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                other_child.data().public_key()
            } else {
                // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                Self::get_last_public_key_on_path(self, agg_root, &path)?
            };
            resulting_target_node.data.co_public_key = Some(pk);
        }

        let agg_tree = BinaryTree::new(Some(resulting_aggregation_root));
        VerifierAggregationTree::try_from(&agg_tree)
    }

    /// Retrieve the last public key on given `path`, by applying required changes from the
    /// `aggregation`.
    pub(crate) fn get_last_public_key_on_path(
        art: &PublicArt<G>,
        aggregation: &BinaryTreeNode<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ArtError> {
        let mut leaf_public_key = art.root().data().public_key();

        let mut current_art_node = Some(art.root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            if let Some(art_node) = current_art_node {
                current_art_node = art_node.child(*dir);
                if let Some(node) = current_art_node
                    && node.is_leaf()
                {
                    leaf_public_key = node.data().public_key();
                }
            }

            if let Some(agg_node) = current_agg_node {
                current_agg_node = agg_node.child(*dir);

                if let Some(node) = current_agg_node {
                    if let Some(pk) = extract_public_key(&node.data, path.get(i + 1)) {
                        leaf_public_key = pk
                    }
                };
            };
        }

        Ok(leaf_public_key)
    }
}

fn extract_public_key<G: AffineRepr>(
    data: &AggregationData<G>,
    next_direction: Option<&Direction>,
) -> Option<G> {
    let mut result = None;
    for change_type in &data.change_type {
        match change_type {
            BranchChangeTypeHint::RemoveMember { pk: blank_pk, .. } => {
                result = Some(*blank_pk);
            }
            BranchChangeTypeHint::AddMember { pk, ext_pk, .. } => {
                if let Some(replacement_pk) = ext_pk {
                    match next_direction {
                        Some(Direction::Right) => result = Some(*pk),
                        Some(Direction::Left) => {}
                        None => result = Some(*replacement_pk),
                    }
                } else {
                    result = Some(*pk);
                }
            }
            BranchChangeTypeHint::UpdateKey { pk } => result = Some(*pk),
            BranchChangeTypeHint::Leave { pk } => result = Some(*pk),
        }
    }

    result
}

impl<G> BranchChange<G>
where
    G: AffineRepr,
{
    pub(crate) fn pub_art_apply_prepare(
        &self,
        art: &PublicArt<G>,
    ) -> Result<(bool, Vec<Direction>), ArtError> {
        let weak_only = if let BranchChangeType::RemoveMember = self.change_type {
            if let node = art.node(&self.node_index)?
                && node.is_leaf()
            {
                matches!(node.data().status(), Some(LeafStatus::Blank))
            } else {
                return Err(ArtError::InvalidBranchChange);
            }
        } else {
            false
        };

        let path = self.node_index.get_path()?;

        Ok((weak_only, path))
    }

    pub(crate) fn pub_art_unrecoverable_apply(
        &self,
        art: &mut PublicArt<G>,
    ) -> Result<(), ArtError> {
        let path = self.node_index.get_path()?;
        match self.change_type {
            BranchChangeType::UpdateKey => art.apply_update_key(&self.public_keys, &path),
            BranchChangeType::AddMember => {
                let target_status = art.node_at(&path)?.data().status();
                let extend_tree = matches!(
                    target_status,
                    Some(LeafStatus::Active | LeafStatus::PendingRemoval)
                );
                art.apply_add_member(&self.public_keys, &path, extend_tree)
            }
            BranchChangeType::RemoveMember => {
                let target_status = art.node_at(&path)?.data().status();
                let weak_only = matches!(target_status, Some(LeafStatus::Blank));
                art.apply_remove_member(&self.public_keys, &path, weak_only)
            }
            BranchChangeType::Leave => art.apply_leave(&self.public_keys, &path),
        }
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let snapshot = art.snapshot();

        if let Err(err) = self.pub_art_unrecoverable_apply(art) {
            art.undo_apply(snapshot);
            return Err(err);
        }

        Ok(())
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let snapshot = art.snapshot();

        if let Err(err) = self.pub_art_unrecoverable_apply(art) {
            art.undo_apply(snapshot);
            return Err(err);
        }

        Ok(())
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for PrivateAggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        self.change().apply(art)
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for AggregationContext<PrivateArt<G>, G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let aggregation = AggregatedChange::try_from(self)?;
        aggregation.apply(art)
    }
}

impl<'a, G> PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    /// Search for a node with the given `public_key`.
    pub fn find(&'a self, public_key: G) -> Result<ArtNodePreview<'a, G>, ArtError> {
        for (node, _) in self.root().node_iter_with_path() {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Search for a leaf node with the given `public_key`.
    pub fn find_leaf(&'a self, public_key: G) -> Result<ArtNodePreview<'a, G>, ArtError> {
        for (node, _) in self.root().node_iter_with_path() {
            if let Some(art_node) = node.art_node()
                && art_node.is_leaf()
                && art_node.data().public_key().eq(&public_key)
            {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Retrieve node by `NodeIndex`.
    pub fn node(&'a self, index: &NodeIndex) -> Result<ArtNodePreview<'a, G>, ArtError> {
        self.node_at(&index.get_path()?)
    }

    /// Retrieve node by the given `path`.
    pub fn node_at(&'a self, path: &[Direction]) -> Result<ArtNodePreview<'a, G>, ArtError> {
        let art_node = self.public_art.root().node_at(path).ok();

        let merge_node = self
            .public_art
            .merge_tree
            .root
            .as_ref()
            .and_then(|root| root.node_at(&path).ok());

        ArtNodePreview::new(art_node, merge_node)
    }

    /// Return a reference on the root preview node.
    pub fn root(&self) -> ArtNodePreview<'a, G> {
        match self.public_art.merge_tree.root.as_ref() {
            None => ArtNodePreview::ArtNodeOnly {
                art_node: &self.public_art.tree_root,
            },
            Some(merge_tree_root) => ArtNodePreview::Full {
                art_node: &self.public_art.tree_root,
                merge_node: &merge_tree_root,
            },
        }
    }

    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn co_path(&self, path: &[Direction]) -> Result<Vec<G>, ArtError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.root();
        for direction in path {
            co_path_values.push(
                parent
                    .child(direction.other())
                    .ok_or(ArtError::PathNotExists)?
                    .public_key(),
            );
            parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    /// Returns helper structure for verification of art update.
    pub fn verification_branch(
        &self,
        change: &BranchChange<G>,
    ) -> Result<Vec<VerifierNodeData<G>>, ArtError> {
        let mut path = change.node_index.get_path()?;
        if matches!(change.change_type, BranchChangeType::AddMember)
            && matches!(
                self.node_at(&path)?.status(),
                Some(LeafStatus::Active | LeafStatus::PendingRemoval)
            )
        {
            path.push(Direction::Right);
        }

        let mut co_path = Vec::new();
        let mut parent = self.root();
        for direction in &path {
            if parent.is_leaf() {
                if let BranchChangeType::AddMember = change.change_type
                    && matches!(parent.status(), Some(LeafStatus::Active))
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.public_key())
                }
            } else {
                co_path.push(
                    parent
                        .child(direction.other())
                        .ok_or(ArtError::PathNotExists)?
                        .public_key(),
                );
                parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
            }
        }

        co_path.reverse();

        let verifier_artefacts = VerifierArtefacts {
            path: change.public_keys.iter().rev().cloned().collect(),
            co_path,
        };

        verifier_artefacts.to_verifier_branch()
    }

    /// Update public art public keys with ones provided in the `verifier_aggregation` tree.
    pub fn verification_tree(
        &self,
        agg: &BinaryTree<AggregationData<G>>,
    ) -> Result<VerifierAggregationTree<G>, ArtError> {
        let agg_root = match agg.root() {
            Some(root) => root,
            None => return Err(ArtError::NoChanges),
        };

        let mut resulting_aggregation_root =
            BinaryTreeNode::<VerifierAggregationData<G>>::try_from(agg_root)?;

        for (_, path) in NodeIterWithPath::new(agg_root).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let resulting_target_node = resulting_aggregation_root.mut_node_at(&parent_path)?;
            let aggregation_parent = path
                .last()
                .ok_or(ArtError::NoChanges)
                .map(|(node, _)| *node)?;

            let last_direction = parent_path.pop().ok_or(ArtError::NoChanges)?;

            // Update co-path
            let pk = if let Ok(co_leaf) = aggregation_parent.node_at(&[last_direction.other()]) {
                // Retrieve co-path from the aggregation
                co_leaf.data.public_key
            } else if let Ok(parent) = self.node_at(&parent_path)
                && let Some(other_child) = parent.child(last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                other_child.public_key()
            } else {
                // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                Self::get_last_public_key_on_path(self, agg_root, &path)?
            };
            resulting_target_node.data.co_public_key = Some(pk);
        }

        let agg_tree = BinaryTree::new(Some(resulting_aggregation_root));
        VerifierAggregationTree::try_from(&agg_tree)
    }

    /// Retrieve the last public key on given `path`, by applying required changes from the
    /// `aggregation`.
    pub(crate) fn get_last_public_key_on_path(
        art: &PublicArtPreview<G>,
        aggregation: &BinaryTreeNode<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ArtError> {
        let mut leaf_public_key = art.root().public_key();

        let mut current_art_node = Some(art.root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            if let Some(art_node) = current_art_node {
                current_art_node = art_node.child(*dir);
                if let Some(leaf) = current_art_node {
                    if leaf.is_leaf() {
                        leaf_public_key = leaf.public_key();
                    }
                }
            }

            if let Some(agg_node) = current_agg_node {
                current_agg_node = agg_node.child(*dir);

                if let Some(node) = current_agg_node {
                    if let Some(pk) = extract_public_key(&node.data, path.get(i + 1)) {
                        leaf_public_key = pk
                    }
                };
            };
        }

        Ok(leaf_public_key)
    }

    pub(crate) fn find_place_for_new_node(&self) -> Result<Vec<Direction>, ArtError> {
        match self.find_path_to_left_most_blank_node() {
            Some(path) => Ok(path),
            None => self.find_path_to_lowest_leaf(),
        }
    }

    /// Searches for the left most blank node and returns the vector of directions to it.
    pub(crate) fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in self.root().node_iter_with_path() {
            if node.is_leaf() && !matches!(node.status(), Some(LeafStatus::Active)) {
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
    pub(crate) fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ArtError> {
        let mut candidate = self.root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate
                .child(Direction::Left)
                .ok_or(ArtError::PathNotExists)?;
            let r = candidate
                .child(Direction::Right)
                .ok_or(ArtError::PathNotExists)?;

            let next_direction = match l.weight() <= r.weight() {
                true => Direction::Left,
                false => Direction::Right,
            };

            next.push(next_direction);
            candidate = candidate
                .child(next_direction)
                .ok_or(ArtError::InvalidInput)?;
        }

        while let (Some(l), Some(r)) = (
            candidate.child(Direction::Left),
            candidate.child(Direction::Right),
        ) {
            if l.weight() <= r.weight() {
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
