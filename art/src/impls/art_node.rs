use crate::errors::ARTNodeError;
use crate::types::{
    ARTDisplayTree, ARTNode, Direction, LeafIter, LeafIterWithPath, LeafStatus, NodeIter,
    NodeIterWithPath,
};
use ark_ec::{AffineRepr, CurveGroup};
use display_tree::{CharSet, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};
use std::mem;

/// Implementation of main methods for operating with ARTNode
impl<G: AffineRepr> ARTNode<G> {
    /// Creates a new ARTNode internal node with the given public key.
    pub fn new_internal_node(public_key: G, l: Box<Self>, r: Box<Self>) -> Self {
        let weight = l.get_weight() + r.get_weight();

        Self::Internal {
            public_key,
            l,
            r,
            weight,
        }
    }

    /// Creates a new ARTNode leaf with the given public key.
    pub fn new_leaf(public_key: G) -> Self {
        Self::Leaf {
            public_key,
            status: LeafStatus::Active,
            metadata: vec![],
        }
    }

    /// Checks it the node is leaf, i.e. both children are None.
    pub fn is_leaf(&self) -> bool {
        match self {
            ARTNode::Leaf { .. } => true,
            ARTNode::Internal { .. } => false,
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

    pub fn get_mut_weight(&mut self) -> Result<&mut usize, ARTNodeError> {
        match self {
            ARTNode::Leaf { .. } => Err(ARTNodeError::InternalNodeOnly),
            ARTNode::Internal { weight, .. } => Ok(weight),
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn get_status(&self) -> Option<LeafStatus> {
        match self {
            ARTNode::Leaf { status, .. } => Some(*status),
            ARTNode::Internal { .. } => None,
        }
    }

    /// Returns true if the node is internal of it is active leaf. Else return False
    pub fn is_active(&self) -> bool {
        match self {
            ARTNode::Leaf { status, .. } => matches!(status, LeafStatus::Active),
            ARTNode::Internal { .. } => true,
        }
    }

    /// If the node is a leaf node, converts the node to blank, else return error
    pub fn make_blank(
        &mut self,
        temporary_public_key: &G,
        append: bool,
    ) -> Result<(), ARTNodeError> {
        match self {
            ARTNode::Leaf { .. } => {
                self.set_status(LeafStatus::Blank)?;
                self.set_public_key_with_options(*temporary_public_key, append);
                Ok(())
            }
            ARTNode::Internal { .. } => Err(ARTNodeError::LeafOnly),
        }
    }

    pub fn set_status(&mut self, new_status: LeafStatus) -> Result<(), ARTNodeError> {
        match self {
            ARTNode::Leaf { status, .. } => {
                *status = new_status;
                Ok(())
            }
            ARTNode::Internal { .. } => Err(ARTNodeError::LeafOnly),
        }
    }

    /// Returns a reference to the left child node.
    pub fn get_left(&self) -> Result<&Self, ARTNodeError> {
        self.get_child(&Direction::Left)
    }

    /// Returns a mutable reference to the left child node.
    pub fn get_mut_left(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        self.get_mut_child(&Direction::Left)
    }

    /// Returns a reference to the right child node.
    pub fn get_right(&self) -> Result<&Self, ARTNodeError> {
        self.get_child(&Direction::Right)
    }

    /// Returns a mutable reference to the right child node.
    pub fn get_mut_right(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        self.get_mut_child(&Direction::Right)
    }

    pub fn set_child(&mut self, other: Self, dir: &Direction) -> Result<(), ARTNodeError> {
        match self {
            ARTNode::Leaf { .. } => Err(ARTNodeError::InternalNodeOnly),
            ARTNode::Internal { l, r, .. } => {
                match dir {
                    Direction::Left => *l.as_mut() = other,
                    Direction::Right => *r.as_mut() = other,
                }

                Ok(())
            }
        }
    }

    /// Changes left child of inner node with a given one
    pub fn set_left(&mut self, other: Self) -> Result<(), ARTNodeError> {
        self.set_child(other, &Direction::Left)
    }

    /// Changes right child of inner node with a given one
    pub fn set_right(&mut self, other: Self) -> Result<(), ARTNodeError> {
        self.set_child(other, &Direction::Right)
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

    pub fn merge_public_key(&mut self, new_public_key: G) {
        let new_public_key = new_public_key.add(self.get_public_key()).into_affine();
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

    /// Returns a reference on a child of a given inner node by a given direction to the child.
    pub fn get_child(&self, child: &Direction) -> Result<&Self, ARTNodeError> {
        match self {
            ARTNode::Leaf { .. } => Err(ARTNodeError::InternalNodeOnly),
            ARTNode::Internal { l, r, .. } => match child {
                Direction::Left => Ok(l.as_ref()),
                Direction::Right => Ok(r.as_ref()),
            },
        }
    }

    /// Returns a mutable reference on a child of a given inner node by a given direction to
    /// the child.
    pub fn get_mut_child(&mut self, child: &Direction) -> Result<&mut Box<Self>, ARTNodeError> {
        match self {
            ARTNode::Leaf { .. } => Err(ARTNodeError::InternalNodeOnly),
            ARTNode::Internal { l, r, .. } => match child {
                Direction::Left => Ok(l),
                Direction::Right => Ok(r),
            },
        }
    }

    /// Returns a reference on a child of a given inner node, which is located on the opposite
    /// side to the given direction.
    pub fn get_other_child(&self, child: &Direction) -> Result<&Self, ARTNodeError> {
        self.get_child(&child.other())
    }

    /// Returns a mutable reference on a child of a given inner node, which is located on the
    /// opposite side to the given direction.
    pub fn get_mut_other_child(
        &mut self,
        child: &Direction,
    ) -> Result<&mut Box<Self>, ARTNodeError> {
        self.get_mut_child(&child.other())
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
    pub fn extend_or_replace(&mut self, other: Self) -> Result<(), ARTNodeError> {
        match self {
            ARTNode::Leaf { status, .. } => {
                match status {
                    LeafStatus::Active => self.extend(other),
                    _ => _ = self.replace_with(other),
                };
            }
            ARTNode::Internal { .. } => return Err(ARTNodeError::LeafOnly),
        }

        Ok(())
    }

    pub fn display_analog(&self) -> ARTDisplayTree {
        let blank_marker = match self {
            ARTNode::Leaf { status, .. } => match status {
                LeafStatus::Active => "Active",
                LeafStatus::PendingRemoval => "PendingRemoval",
                LeafStatus::Blank => "Blank",
            },
            ARTNode::Internal { .. } => "",
        };

        let pk_marker = match self.get_public_key().x() {
            Some(x) => x.to_string(),
            None => "None".to_string(),
        };

        match self {
            ARTNode::Leaf { .. } => ARTDisplayTree::Leaf {
                public_key: format!(
                    "{} leaf of weight: {}, x: {}",
                    blank_marker,
                    self.get_weight(),
                    pk_marker,
                ),
            },
            ARTNode::Internal { .. } => ARTDisplayTree::Inner {
                public_key: format!("Node of weight: {}, x: {}", self.get_weight(), pk_marker,),
                left: Box::new(self.get_left().unwrap().display_analog()),
                right: Box::new(self.get_right().unwrap().display_analog()),
            },
        }
    }

    pub(crate) fn new_default_tree_with_public_keys(
        public_keys: &Vec<G>,
    ) -> Result<Self, ARTNodeError> {
        if public_keys.is_empty() {
            return Err(ARTNodeError::InvalidParameters);
        }

        let mut level_nodes = Vec::new();

        // leaves of the tree
        for pk in public_keys {
            level_nodes.push(ARTNode::new_leaf(*pk));
        }

        // fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            level_nodes = Self::fit_leaves_in_one_level(level_nodes)?;
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            level_nodes = Self::compute_next_layer_of_tree(&mut level_nodes)?;
        }

        let root = level_nodes.remove(0);

        Ok(root)
    }

    fn fit_leaves_in_one_level(
        mut level_nodes: Vec<ARTNode<G>>,
    ) -> Result<Vec<ARTNode<G>>, ARTNodeError> {
        let mut level_size = 2;
        while level_size < level_nodes.len() {
            level_size <<= 1;
        }

        if level_size == level_nodes.len() {
            return Ok(level_nodes);
        }

        let excess = level_size - level_nodes.len();

        let mut upper_level_nodes = Vec::new();
        for _ in 0..(level_nodes.len() - excess) >> 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            let node = ARTNode::new_internal_node(
                (left_node.get_public_key() + right_node.get_public_key()).into_affine(),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
        }

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
        }

        Ok(upper_level_nodes)
    }

    fn compute_next_layer_of_tree(
        level_nodes: &mut Vec<ARTNode<G>>,
    ) -> Result<Vec<ARTNode<G>>, ARTNodeError> {
        let mut upper_level_nodes = Vec::new();

        // iterate until level_nodes is empty, then swap it with the next layer
        while level_nodes.len() > 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            let node = ARTNode::new_internal_node(
                (left_node.get_public_key() + right_node.get_public_key()).into_affine(),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
        }

        // if one have an odd number of nodes, the last one will be added to the next level
        if level_nodes.len() == 1 {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
        }

        Ok(upper_level_nodes)
    }
}

impl<G> Default for ARTNode<G>
where
    G: AffineRepr,
{
    fn default() -> Self {
        Self::new_leaf(G::zero())
    }
}

impl<G> Display for ARTNode<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_tree!(
                self.display_analog(),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::SINGLE_LINE)
            )
        )
    }
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, G> NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
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
    type Item = (&'a ARTNode<G>, Vec<(&'a ARTNode<G>, Direction)>);

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
                                self.current_node = parent.get_right().ok();
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
                self.current_node = current_node.get_left().ok();
            }

            Some(return_item)
        } else {
            None
        }
    }
}

/// LeafIterWithPath iterates ove leaves from left most to right most
impl<'a, G> LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
        LeafIterWithPath {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    type Item = (&'a ARTNode<G>, Vec<(&'a ARTNode<G>, Direction)>);

    fn next(&mut self) -> Option<Self::Item> {
        for (item, path) in &mut self.inner_iter {
            if item.is_leaf() {
                return Some((item, path));
            }
        }

        None
    }
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, G> NodeIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
        NodeIter {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for NodeIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ARTNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter.next().map(|item| item.0)
    }
}

/// LeafIter iterates ove leaves from left most to right most
impl<'a, G> LeafIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
        LeafIter {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, G> Iterator for LeafIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ARTNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        (&mut self.inner_iter)
            .map(|(item, _)| item)
            .find(|&item| item.is_leaf())
    }
}

/// Default iterator iterates over all the leaves from left to right
impl<'a, G> IntoIterator for &'a ARTNode<G>
where
    G: AffineRepr,
{
    type Item = &'a ARTNode<G>;
    type IntoIter = LeafIter<'a, G>;

    fn into_iter(self) -> Self::IntoIter {
        LeafIter::new(self)
    }
}

impl Default for LeafStatus {
    fn default() -> Self {
        Self::Active
    }
}
