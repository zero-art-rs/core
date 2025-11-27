use crate::art::artefacts::VerifierArtefacts;
use crate::art_node::{ArtNode, LeafStatus, NodeIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{AggregationNode, AggregationTree, TreeNodeIterWithPath};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::fmt::Debug;
use std::mem;
use zrt_zk::art::VerifierNodeData;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
pub struct PublicMergeData<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) strong_key: Option<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) weak_key: Option<G>,
    pub(crate) status: Option<LeafStatus>,
    pub(crate) weight_change: i32,
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
    pub fn weak_key(&self) -> Option<G> {
        self.weak_key
    }

    pub fn mut_weak_key(&mut self) -> &mut Option<G> {
        &mut self.weak_key
    }

    pub fn strong_key(&self) -> Option<G> {
        self.strong_key
    }

    pub fn mut_strong_key(&mut self) -> &mut Option<G> {
        &mut self.strong_key
    }

    pub fn status(&self) -> Option<LeafStatus> {
        self.status
    }

    pub fn update_weight_change(&mut self, increment: bool) {
        if increment {
            self.weight_change += 1;
        } else {
            self.weight_change -= 1;
        }
    }

    pub fn update_status(&mut self, status: LeafStatus) {
        if let Some(inner_status) = &mut self.status {
            *inner_status = max(status, *inner_status);
        } else {
            self.status = Some(status);
        }
    }

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
    pub(crate) merge_tree: AggregationTree<PublicMergeData<G>>,
}

pub struct PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    public_art: &'a PublicArt<G>,
}

#[derive(Clone, Copy, Debug)]
pub enum ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    ArtNodeOnly {
        art_node: &'a ArtNode<G>,
    },
    MergeNodeOnly {
        merge_node: &'a AggregationNode<PublicMergeData<G>>,
    },
    Full {
        art_node: &'a ArtNode<G>,
        merge_node: &'a AggregationNode<PublicMergeData<G>>,
    },
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

    pub fn discard(&mut self) {
        self.merge_tree = Default::default();
    }

    fn inner_commit(
        &mut self,
        merge_tree: &AggregationNode<PublicMergeData<G>>,
    ) -> Result<(), ArtError> {
        for (merge_node, path_data) in merge_tree.node_iter_with_path() {
            let path = path_data.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let art_node = self.mut_root().mut_node_at(&path)?;

            if art_node.is_leaf() && !merge_node.is_leaf() {
                let public_key = merge_node
                    .child(Direction::Right)
                    .ok_or(ArtError::InvalidBranchChange)?
                    .preview_public_key();
                art_node.extend(ArtNode::new_leaf(public_key));
                art_node.commit(Some(&merge_node.data))?;
            } else {
                art_node.commit(Some(&merge_node.data))?;
            }
        }

        Ok(())
    }

    pub fn find(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.root()) {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn find_leaf(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.root()) {
            if node.is_leaf() && node.public_key().eq(&public_key) {
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

    pub fn preview(&self) -> PublicArtPreview<G> {
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
            let public_key = target_node.public_key();
            let Some(status) = target_node.status() else {
                return Err(ArtError::InvalidBranchChange);
            };

            let merge_leaf = self.merge_tree.add_branch_keys(
                &public_keys[..public_keys.len() - 1],
                path,
                false,
                Some(true),
            )?;

            *merge_leaf.mut_child(Direction::Right) = Some(Box::new(AggregationNode::new_leaf(
                PublicMergeData::new(Some(new_leaf_public_key), None, Some(LeafStatus::Active), 0),
            )));
            *merge_leaf.mut_child(Direction::Left) = Some(Box::new(AggregationNode::new_leaf(
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
    pub(crate) fn verification_branch(
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
            if let ArtNode::Leaf { status, .. } = art.node(&self.node_index)? {
                matches!(status, LeafStatus::Blank)
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
                let target_status = art.node_at(&path)?.status();
                let extend_tree = matches!(
                    target_status,
                    Some(LeafStatus::Active | LeafStatus::PendingRemoval)
                );
                art.apply_add_member(&self.public_keys, &path, extend_tree)
            }
            BranchChangeType::RemoveMember => {
                let target_status = art.node_at(&path)?.status();
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
        let merge_tree_reserve_copy = art.merge_tree.clone();

        if let Err(err) = self.pub_art_unrecoverable_apply(art) {
            art.merge_tree = merge_tree_reserve_copy;
            return Err(err);
        }

        Ok(())
    }
}

impl<'a, G> PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    pub fn find(&self, public_key: G) -> Result<ArtNodePreview<G>, ArtError> {
        for (node, _) in TreeNodeIterWithPath::new(self.root()) {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn find_leaf(&self, public_key: G) -> Result<ArtNodePreview<G>, ArtError> {
        for (node, _) in TreeNodeIterWithPath::new(self.root()) {
            if let Some(art_node) = node.art_node()
                && art_node.is_leaf()
                && art_node.public_key().eq(&public_key)
            {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn node(&self, index: &NodeIndex) -> Result<ArtNodePreview<G>, ArtError> {
        self.node_at(&index.get_path()?)
    }

    pub fn node_at(&self, path: &[Direction]) -> Result<ArtNodePreview<G>, ArtError> {
        let art_node = self.public_art.root().node_at(path).ok();

        let merge_node = self
            .public_art
            .merge_tree
            .root
            .as_ref()
            .and_then(|root| root.node_at(&path).ok());

        ArtNodePreview::new(art_node, merge_node)
    }

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
    pub(crate) fn verification_branch(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<VerifierArtefacts<G>, ArtError> {
        let mut co_path = Vec::new();

        let mut parent = self.root();
        for direction in &changes.node_index.get_path()? {
            if parent.is_leaf() {
                if let BranchChangeType::AddMember = changes.change_type
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

        Ok(VerifierArtefacts {
            path: changes.public_keys.iter().rev().cloned().collect(),
            co_path,
        })
    }
}

impl<'a, G> ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    pub fn new(
        art_node: Option<&'a ArtNode<G>>,
        merge_node: Option<&'a AggregationNode<PublicMergeData<G>>>,
    ) -> Result<Self, ArtError> {
        match (art_node, merge_node) {
            (Some(art_node), Some(merge_node)) => Ok(Self::Full {
                art_node,
                merge_node,
            }),
            (Some(art_node), None) => Ok(Self::ArtNodeOnly { art_node }),
            (None, Some(merge_node)) => Ok(Self::MergeNodeOnly { merge_node }),
            (None, None) => Err(ArtError::InvalidInput),
        }
    }

    pub fn art_node(&self) -> Option<&'a ArtNode<G>> {
        match self {
            Self::ArtNodeOnly { art_node, .. } => Some(art_node),
            Self::MergeNodeOnly { .. } => None,
            Self::Full { art_node, .. } => Some(art_node),
        }
    }

    /// If exists, returns a reference on the node with the given index, in correspondence to the
    /// root node. Else return `ArtError`.
    pub fn node(&self, index: &NodeIndex) -> Result<Self, ArtError> {
        self.node_at(&index.get_path()?)
    }

    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    pub fn node_at(&self, path: &[Direction]) -> Result<Self, ArtError> {
        let mut node = self.clone();
        for direction in path {
            if let Some(child_node) = node.child(*direction) {
                node = child_node;
            } else {
                return Err(ArtError::PathNotExists);
            }
        }

        Ok(node)
    }

    pub(crate) fn merge_node(&self) -> Option<&'a AggregationNode<PublicMergeData<G>>> {
        match self {
            Self::ArtNodeOnly { .. } => None,
            Self::MergeNodeOnly { merge_node, .. } => Some(merge_node),
            Self::Full { merge_node, .. } => Some(merge_node),
        }
    }

    pub fn public_key(&self) -> G {
        match self {
            Self::ArtNodeOnly { art_node } => art_node.public_key(),
            Self::MergeNodeOnly { merge_node } => merge_node.preview_public_key(),
            Self::Full {
                art_node,
                merge_node,
            } => art_node.preview_public_key(&merge_node.data),
        }
    }

    pub fn status(&self) -> Option<LeafStatus> {
        match self {
            Self::ArtNodeOnly { art_node } => art_node.status(),
            Self::MergeNodeOnly { merge_node } => merge_node.status(),
            Self::Full { merge_node, .. } => merge_node.status(),
        }
    }

    pub fn child(&self, dir: Direction) -> Option<Self> {
        let art_node: Option<&'a ArtNode<G>> = match self.art_node() {
            Some(node) => node.child(dir),
            None => None,
        };

        let merge_node = match self.merge_node() {
            Some(merge_node) => merge_node.child(dir),
            None => None,
        };

        Self::new(art_node, merge_node).ok()
    }

    pub fn is_leaf(&self) -> bool {
        let left = self.child(Direction::Left);
        let right = self.child(Direction::Right);

        left.is_none() && right.is_none()
    }
}
