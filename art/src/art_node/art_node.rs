use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se};
use crate::node_index::Direction;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem;

#[derive(Deserialize, Serialize, Default, Debug, Clone, Copy, Eq, PartialEq)]
#[serde(bound = "")]
pub enum LeafStatus {
    #[default]
    Active,
    PendingRemoval,
    Blank,
}

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(bound = "")]
pub enum ArtNode<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    Leaf {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        status: LeafStatus,
        metadata: Vec<u8>,
    },
    Internal {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        l: Box<ArtNode<G>>,
        r: Box<ArtNode<G>>,
        weight: usize,
    },
}

impl<G> Default for ArtNode<G>
where
    G: AffineRepr,
{
    fn default() -> Self {
        Self::new_leaf(G::zero())
    }
}

impl<G> ArtNode<G>
where
    G: AffineRepr,
{
    /// Creates a new ArtNode leaf with the given public key.
    pub fn new_leaf(public_key: G) -> Self {
        Self::Leaf {
            public_key,
            status: LeafStatus::Active,
            metadata: vec![],
        }
    }

    /// Creates a new ArtNode internal node with the given public key.
    pub fn new_internal_node(public_key: G, l: Box<Self>, r: Box<Self>) -> Self {
        let weight = l.get_weight() + r.get_weight();

        Self::Internal {
            public_key,
            l,
            r,
            weight,
        }
    }

    /// Returns the weight of the node.
    pub fn get_weight(&self) -> usize {
        match self {
            Self::Internal { weight, .. } => *weight,
            Self::Leaf { status, .. } => match status {
                LeafStatus::Active => 1,
                _ => 0,
            },
        }
    }

    pub fn get_mut_weight(&mut self) -> Result<&mut usize, ArtError> {
        match self {
            ArtNode::Leaf { .. } => Err(ArtError::InternalNodeOnly),
            ArtNode::Internal { weight, .. } => Ok(weight),
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn get_status(&self) -> Option<LeafStatus> {
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
    pub fn get_public_key(&self) -> G {
        match self {
            Self::Internal { public_key, .. } => *public_key,
            Self::Leaf { public_key, .. } => *public_key,
        }
    }

    pub fn set_public_key(&mut self, new_public_key: G) {
        match self {
            Self::Internal { public_key, .. } => *public_key = new_public_key,
            Self::Leaf { public_key, .. } => *public_key = new_public_key,
        }
    }

    pub fn set_public_key_with_options(&mut self, new_public_key: G, append: bool) {
        let new_public_key = match append {
            true => new_public_key.add(self.get_public_key()).into_affine(),
            false => new_public_key,
        };

        self.set_public_key(new_public_key);
    }

    pub fn merge_public_key(&mut self, new_public_key: G) {
        self.set_public_key(new_public_key.add(self.get_public_key()).into_affine());
    }

    pub fn get_child(&self, child: Direction) -> Option<&Self> {
        match self {
            ArtNode::Leaf { .. } => None,
            ArtNode::Internal { l, r, .. } => match child {
                Direction::Left => Some(l.as_ref()),
                Direction::Right => Some(r.as_ref()),
            },
        }
    }

    pub fn get_left(&self) -> Option<&Self> {
        self.get_child(Direction::Left)
    }

    pub fn get_right(&self) -> Option<&Self> {
        self.get_child(Direction::Right)
    }

    pub fn get_mut_child(&mut self, child: Direction) -> Option<&mut Self> {
        match self {
            ArtNode::Leaf { .. } => None,
            ArtNode::Internal { l, r, .. } => match child {
                Direction::Left => Some(l.as_mut()),
                Direction::Right => Some(r.as_mut()),
            },
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, ArtNode::Leaf { .. })
    }

    /// Move current node down to left child, and append other node to the right. The current node
    /// becomes internal.
    pub fn extend(&mut self, other: Self) {
        let new_weight = self.get_weight() + other.get_weight();

        let mut tmp = Self::default();
        mem::swap(self, &mut tmp);

        let mut new_self = Self::Internal {
            public_key: self.get_public_key(),
            l: Box::new(tmp),
            r: Box::new(other),
            weight: new_weight,
        };

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
        match self {
            ArtNode::Leaf { status, .. } => {
                match status {
                    LeafStatus::Active => self.extend(other),
                    _ => _ = self.replace_with(other),
                };
            }
            ArtNode::Internal { .. } => return Err(ArtError::LeafOnly),
        }

        Ok(())
    }

    /// Increment or decrement weight by 1. Return error for leaf node.
    pub(crate) fn update_weight(&mut self, increment: bool) -> Result<(), ArtError> {
        match self {
            ArtNode::Leaf { .. } => return Err(ArtError::InternalNodeOnly),
            ArtNode::Internal { weight, .. } => match increment {
                true => *weight += 1,
                false => *weight -= 1,
            },
        }

        Ok(())
    }
}

pub struct NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub current_node: Option<&'a ArtNode<G>>,
    pub path: Vec<(&'a ArtNode<G>, Direction)>,
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, G> NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ArtNode<G>) -> Self {
        NodeIterWithPath {
            current_node: Some(root),
            path: vec![],
        }
    }
}

impl<'a, G> Iterator for NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    type Item = (&'a ArtNode<G>, Vec<(&'a ArtNode<G>, Direction)>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_node) = self.current_node {
            let return_item = (current_node, self.path.clone());

            if current_node.is_leaf() {
                loop {
                    match self.path.pop() {
                        Some((parent, last_direction)) => {
                            if last_direction == Direction::Right {
                                self.current_node = Some(parent);
                            } else if last_direction == Direction::Left {
                                self.path.push((parent, Direction::Right));
                                self.current_node = parent.get_child(Direction::Right);
                                break;
                            }
                        }
                        None => {
                            self.current_node = None;
                            return Some(return_item);
                        }
                    }
                }
            } else {
                self.path.push((current_node, Direction::Left));
                self.current_node = current_node.get_child(Direction::Left);
            }

            Some(return_item)
        } else {
            None
        }
    }
}

pub struct LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}

/// LeafIterWithPath iterates ove leaves from left most to right most
impl<'a, G> LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ArtNode<G>) -> Self {
        LeafIterWithPath {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    type Item = (&'a ArtNode<G>, Vec<(&'a ArtNode<G>, Direction)>);

    fn next(&mut self) -> Option<Self::Item> {
        for (item, path) in &mut self.inner_iter {
            if item.is_leaf() {
                return Some((item, path));
            }
        }

        None
    }
}

pub struct NodeIter<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, G> NodeIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ArtNode<G>) -> Self {
        NodeIter {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for NodeIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ArtNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter.next().map(|item| item.0)
    }
}

pub struct LeafIter<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}

/// LeafIter iterates ove leaves from left most to right most
impl<'a, G> LeafIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ArtNode<G>) -> Self {
        LeafIter {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for LeafIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ArtNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        (&mut self.inner_iter)
            .map(|(item, _)| item)
            .find(|&item| item.is_leaf())
    }
}

/// Default iterator iterates over all the leaves from left to right
impl<'a, G> IntoIterator for &'a ArtNode<G>
where
    G: AffineRepr,
{
    type Item = &'a ArtNode<G>;
    type IntoIter = LeafIter<'a, G>;

    fn into_iter(self) -> Self::IntoIter {
        LeafIter::new(self)
    }
}
