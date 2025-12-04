use crate::art::PublicMergeData;
use crate::art_node::{BinaryTreeNode, LeafIter, LeafIterWithPath, NodeIter, NodeIterWithPath};
use crate::changes::branch_change::{BranchChangeType, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::mem;

/// Status of the `ArtNode` leaf.
#[derive(Debug, Deserialize, Serialize, Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
#[serde(bound = "")]
pub enum LeafStatus {
    #[default]
    Active,
    PendingRemoval,
    Blank,
}

impl From<&BranchChangeType> for LeafStatus {
    fn from(value: &BranchChangeType) -> Self {
        match value {
            BranchChangeType::RemoveMember => LeafStatus::Blank,
            BranchChangeType::AddMember => LeafStatus::Active,
            BranchChangeType::UpdateKey => LeafStatus::Active,
            BranchChangeType::Leave => LeafStatus::PendingRemoval,
        }
    }
}

impl<G> From<&BranchChangeTypeHint<G>> for LeafStatus
where
    G: AffineRepr,
{
    fn from(value: &BranchChangeTypeHint<G>) -> Self {
        match value {
            BranchChangeTypeHint::RemoveMember { .. } => LeafStatus::Blank,
            BranchChangeTypeHint::AddMember { .. } => LeafStatus::Active,
            BranchChangeTypeHint::UpdateKey { .. } => LeafStatus::Active,
            BranchChangeTypeHint::Leave { .. } => LeafStatus::PendingRemoval,
        }
    }
}

/// The node in the ART tree.
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(bound = "")]
pub enum ArtNodeData<G: AffineRepr> {
    Leaf {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        status: LeafStatus,
        metadata: Vec<u8>,
    },
    Internal {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        weight: usize,
    },
}

impl<G: AffineRepr> ArtNodeData<G> {
    pub fn new_internal(public_key: G, weight: usize) -> Self {
        Self::Internal { public_key, weight }
    }

    pub fn new_leaf(public_key: G, status: LeafStatus, metadata: Vec<u8>) -> Self {
        Self::Leaf {
            public_key,
            status,
            metadata,
        }
    }

    /// Returns the weight of the node.
    pub fn weight(&self) -> usize {
        match self {
            Self::Internal { weight, .. } => *weight,
            Self::Leaf { status, .. } => match status {
                LeafStatus::Active => 1,
                _ => 0,
            },
        }
    }

    pub fn mut_weight(&mut self) -> Result<&mut usize, ArtError> {
        match self {
            Self::Leaf { .. } => Err(ArtError::InternalNodeOnly),
            Self::Internal { weight, .. } => Ok(weight),
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn status(&self) -> Option<LeafStatus> {
        match self {
            Self::Leaf { status, .. } => Some(*status),
            Self::Internal { .. } => None,
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn set_status(&mut self, new_status: LeafStatus) -> Result<(), ArtError> {
        match self {
            Self::Leaf { status, .. } => *status = new_status,
            Self::Internal { .. } => return Err(ArtError::LeafOnly),
        }

        Ok(())
    }

    // Returns a copy of its public key
    pub fn public_key(&self) -> G {
        match self {
            Self::Internal { public_key, .. } => *public_key,
            Self::Leaf { public_key, .. } => *public_key,
        }
    }

    pub fn mut_public_key(&mut self) -> &mut G {
        match self {
            Self::Internal { public_key, .. } => public_key,
            Self::Leaf { public_key, .. } => public_key,
        }
    }
}

pub type ArtNode<G> = BinaryTreeNode<ArtNodeData<G>>;

impl<G> Default for ArtNode<G>
where
    G: AffineRepr,
{
    fn default() -> Self {
        Self::new_leaf(ArtNodeData::new_leaf(G::zero(), Default::default(), vec![]))
    }
}

impl<G> ArtNode<G>
where
    G: AffineRepr,
{
    pub fn full_node(data: ArtNodeData<G>, l: Box<Self>, r: Box<Self>) -> Self {
        Self {
            l: Some(l),
            r: Some(r),
            data,
        }
    }

    /// Move current node down to left child, and append other node to the right. The current node
    /// becomes internal.
    pub fn extend(&mut self, other: Self) {
        let weight = self.data().weight() + other.data().weight();

        let mut tmp = Self::default();
        mem::swap(self, &mut tmp);

        let public_key = self.data().public_key();
        let mut new_self = Self::new_internal(
            ArtNodeData::Internal { public_key, weight },
            Some(Box::new(tmp)),
            Some(Box::new(other)),
        );

        mem::swap(&mut new_self, self);
    }

    /// Changes values of the node with the values of the given one.
    pub fn replace_with(&mut self, mut other: Self) -> Self {
        mem::swap(self, &mut other);
        other
    }

    /// If the node is temporary, replace the node, else moves current node down to left,
    /// and append other node to the right.
    pub fn extend_or_replace(&mut self, other: Self) -> Result<(), ArtError> {
        match self.data().status() {
            Some(LeafStatus::Active | LeafStatus::PendingRemoval) => self.extend(other),
            Some(LeafStatus::Blank) => _ = self.replace_with(other),
            None => return Err(ArtError::LeafOnly),
        }

        Ok(())
    }

    /// If exists, return a reference on the leaf with the provided `public_key`. Else return `ArtError`.
    pub fn leaf_with(&self, public_key: G) -> Result<&Self, ArtError> {
        for (node, _) in LeafIterWithPath::new(self) {
            if node.is_leaf() && node.data().public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// If exists, return a mutable reference on the node with the provided `public_key`. Else return `ArtError`.
    pub fn node_with(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in LeafIterWithPath::new(self) {
            if node.data().public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Searches for a leaf with the provided `public_key`. If there is no such leaf, return `ArtError`.
    pub fn path_to_leaf_with(&self, public_key: G) -> Result<Vec<Direction>, ArtError> {
        for (node, path) in LeafIterWithPath::new(self) {
            if node.is_leaf() && node.data().public_key().eq(&public_key) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub(crate) fn preview_public_key(&self, merge_data: &PublicMergeData<G>) -> G {
        let mut resulting_public_key = self.data().public_key();

        if let Some(strong_key) = &merge_data.strong_key {
            resulting_public_key = *strong_key;
        }

        if let Some(weak_key) = &merge_data.weak_key {
            resulting_public_key = resulting_public_key.add(weak_key).into_affine();
        }

        resulting_public_key
    }

    pub(crate) fn commit(
        &mut self,
        merge_data: Option<&PublicMergeData<G>>,
    ) -> Result<G, ArtError> {
        if let Some(merge_data) = merge_data {
            *self.data.mut_public_key() = self.preview_public_key(merge_data);

            if let Some(status) = &merge_data.status {
                self.data.set_status(*status)?;
            }

            if let Ok(weight) = self.data.mut_weight() {
                match merge_data.weight_change.cmp(&0) {
                    Ordering::Less => *weight -= merge_data.weight_change.abs() as usize,
                    Ordering::Equal => {}
                    Ordering::Greater => *weight += merge_data.weight_change as usize,
                }
            }
        };

        Ok(self.data().public_key())
    }
}

/// A view of the `ArtNode` in  `PublicArt` state after commit.
#[derive(Clone, Copy, Debug)]
pub enum ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    ArtNodeOnly {
        art_node: &'a ArtNode<G>,
    },
    MergeNodeOnly {
        merge_node: &'a BinaryTreeNode<PublicMergeData<G>>,
    },
    Full {
        art_node: &'a ArtNode<G>,
        merge_node: &'a BinaryTreeNode<PublicMergeData<G>>,
    },
}

impl<'a, G> ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    pub fn new(
        art_node: Option<&'a ArtNode<G>>,
        merge_node: Option<&'a BinaryTreeNode<PublicMergeData<G>>>,
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

    /// Returns reference on the corresponding `ArtNode`.
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

    /// If exists, return a reference on the leaf with the provided `public_key`. Else return `ArtError`.
    pub fn leaf_with(&self, public_key: G) -> Result<Self, ArtError> {
        for node in self.leaf_iter() {
            if node.is_leaf() && node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// If exists, return a mutable reference on the node with the provided `public_key`. Else return `ArtError`.
    pub fn node_with(&self, public_key: G) -> Result<Self, ArtError> {
        for node in self.leaf_iter() {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Returns merge node is exists, else `None`.
    pub(crate) fn merge_node(&self) -> Option<&'a BinaryTreeNode<PublicMergeData<G>>> {
        match self {
            Self::ArtNodeOnly { .. } => None,
            Self::MergeNodeOnly { merge_node, .. } => Some(merge_node),
            Self::Full { merge_node, .. } => Some(merge_node),
        }
    }

    pub fn public_key(&self) -> G {
        match self {
            Self::ArtNodeOnly { art_node } => art_node.data().public_key(),
            Self::MergeNodeOnly { merge_node } => merge_node.preview_public_key(),
            Self::Full {
                art_node,
                merge_node,
            } => art_node.preview_public_key(&merge_node.data),
        }
    }

    pub fn status(&self) -> Option<LeafStatus> {
        match self {
            Self::ArtNodeOnly { art_node } => art_node.data().status(),
            Self::MergeNodeOnly { merge_node } => merge_node.status(),
            Self::Full { merge_node, .. } => merge_node.status(),
        }
    }

    pub fn weight(&self) -> usize {
        match self {
            Self::ArtNodeOnly { art_node } => art_node.data().weight(),
            Self::MergeNodeOnly { merge_node } => merge_node.data.weight_change as usize,
            Self::Full {
                merge_node,
                art_node,
            } => {
                let mut weight = art_node.data().weight();
                match merge_node.data.weight_change.cmp(&0) {
                    Ordering::Less => weight -= merge_node.data.weight_change.abs() as usize,
                    Ordering::Equal => {}
                    Ordering::Greater => weight += merge_node.data.weight_change as usize,
                }

                weight
            }
        }
    }

    /// Returns a children node on the given direction `dir` if exists, else `None`.
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

    pub fn node_iter_with_path(&self) -> NodeIterWithPath<Self> {
        NodeIterWithPath::new(self.clone())
    }

    pub fn leaf_iter_with_path(&self) -> LeafIterWithPath<Self> {
        LeafIterWithPath::new(self.clone())
    }

    pub fn node_iter(&self) -> NodeIter<Self> {
        NodeIter::new(self.clone())
    }

    pub fn leaf_iter(&self) -> LeafIter<Self> {
        LeafIter::new(self.clone())
    }
}
