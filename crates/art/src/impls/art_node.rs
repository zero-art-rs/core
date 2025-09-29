use crate::errors::ARTNodeError;
use crate::types::{
    ARTDisplayTree, ARTNode, Direction, LeafIter, LeafIterWithPath, NodeIter, NodeIterWithPath,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::{CharSet, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};
use tracing::debug;

/// Implementation of main methods for operating with ARTNode
impl<G: AffineRepr> ARTNode<G> {
    /// Creates a new ARTNode internal node with the given public key.
    pub fn new_internal_node(public_key: G, l: Box<Self>, r: Box<Self>) -> Self {
        let weight = l.weight + r.weight;

        Self {
            public_key,
            l: Some(l),
            r: Some(r),
            is_blank: false,
            weight,
            metadata: None,
        }
    }

    /// Creates a new ARTNode leaf with the given public key.
    pub fn new_leaf(public_key: G) -> Self {
        Self {
            public_key,
            l: None,
            r: None,
            is_blank: false,
            weight: 1,
            metadata: None,
        }
    }

    /// Checks it the node is leaf, i.e. both children are None.
    pub fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    /// Returns a reference to the left child node.
    pub fn get_left(&self) -> Result<&Box<Self>, ARTNodeError> {
        match &self.l {
            Some(l) => Ok(l),
            None => Err(ARTNodeError::InternalNodeOnly),
        }
    }

    /// If the node is a leaf node, converts the node to blank, else return error
    pub fn make_blank(
        &mut self,
        temporary_public_key: &G,
        append: bool,
    ) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            self.set_public_key_with_options(temporary_public_key.clone(), append);
            self.is_blank = true;
            self.weight = 0;
            Ok(())
        } else {
            Err(ARTNodeError::LeafOnly)
        }
    }

    /// Returns a mutable reference to the left child node.
    pub fn get_mut_left(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        match &mut self.l {
            Some(l) => Ok(l),
            None => Err(ARTNodeError::InternalNodeOnly),
        }
    }

    /// Returns a reference to the right child node.
    pub fn get_right(&self) -> Result<&Box<Self>, ARTNodeError> {
        match &self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly),
        }
    }

    /// Returns a mutable reference to the right child node.
    pub fn get_mut_right(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        match &mut self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly),
        }
    }

    /// Changes left child of inner node with a given one
    pub fn set_left(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        self.l = Some(Box::new(other));
        self.weight = self.get_right()?.weight + self.get_left()?.weight;

        Ok(())
    }

    /// Changes right child of inner node with a given one
    pub fn set_right(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        self.r = Some(Box::new(other));
        self.weight = self.get_right()?.weight + self.get_left()?.weight;

        Ok(())
    }

    // Returns a copy of its public key
    pub fn get_public_key(&self) -> G {
        self.public_key.clone()
    }

    pub fn set_public_key(&mut self, public_key: G) {
        self.set_public_key_with_options(public_key, false)
    }

    pub fn set_public_key_with_options(&mut self, public_key: G, append: bool) {
        match append {
            true => self.public_key = public_key.add(self.public_key).into_affine(),
            false => self.public_key = public_key,
        }
    }

    /// Returns a reference on a child of a given inner node by a given direction to the child.
    pub fn get_child(&self, child: &Direction) -> Result<&Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        match child {
            Direction::Left => Ok(self.get_left()?),
            Direction::Right => Ok(self.get_right()?),
        }
    }

    /// Returns a mutable reference on a child of a given inner node by a given direction to
    /// the child.
    pub fn get_mut_child(&mut self, child: &Direction) -> Result<&mut Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        match child {
            Direction::Left => Ok(self.get_mut_left()?),
            Direction::Right => Ok(self.get_mut_right()?),
        }
    }

    /// Returns a reference on a child of a given inner node, which is located on the opposite
    /// side to the given direction.
    pub fn get_other_child(&self, child: &Direction) -> Result<&Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        match child {
            Direction::Left => Ok(self.get_right()?),
            Direction::Right => Ok(self.get_left()?),
        }
    }

    /// Returns a mutable reference on a child of a given inner node, which is located on the
    /// opposite side to the given direction.
    pub fn get_mut_other_child(
        &mut self,
        child: &Direction,
    ) -> Result<&mut Box<Self>, ARTNodeError> {
        match child {
            Direction::Left => Ok(self.r.as_mut().ok_or(ARTNodeError::InternalNodeOnly)?),
            Direction::Right => Ok(self.l.as_mut().ok_or(ARTNodeError::InternalNodeOnly)?),
        }
    }

    /// Move current node down to left child, and append other node to the right. The current node
    /// becomes internal.
    pub fn extend(&mut self, other: Self) {
        let new_self = Self {
            public_key: self.public_key.clone(),
            l: self.l.take(),
            r: self.r.take(),
            is_blank: false,
            weight: self.weight,
            metadata: self.metadata.clone(),
        };

        self.weight = other.weight + new_self.weight;
        self.l = Some(Box::new(new_self));
        self.r = Some(Box::new(other));
        self.metadata = None
    }

    /// Changes values of the node with the values of the given one.
    pub fn replace_with(&mut self, mut other: Self) -> Self {
        std::mem::swap(self, &mut other);
        other

        // self.set_public_key(other.get_public_key());
        // self.l = other.l;
        // self.r = other.r;
        // self.is_blank = other.is_blank;
        // self.weight = other.weight;
        // self.metadata = other.metadata;
    }

    /// If the node is temporary, replace the node, else moves current node down to left,
    /// and append other node to the right.
    pub fn extend_or_replace(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if !self.is_leaf() {
            return Err(ARTNodeError::LeafOnly);
        }

        match self.is_blank {
            true => _ = self.replace_with(other),
            false => self.extend(other),
        }

        Ok(())
    }

    /// Change current node with its child. Other child is removed and returned.
    pub fn shrink_to(&mut self, child: Direction) -> Result<Option<Box<Self>>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly);
        }

        let (new_self, other_child) = match child {
            Direction::Left => (self.l.take(), self.r.take()),
            Direction::Right => (self.r.take(), self.l.take()),
        };

        let mut new_self = new_self.ok_or(ARTNodeError::InternalNodeOnly)?;

        self.weight = new_self.weight;
        self.public_key = new_self.public_key.clone();
        self.l = new_self.l.take();
        self.r = new_self.r.take();
        self.is_blank = new_self.is_blank;
        self.metadata = new_self.metadata.clone();

        Ok(other_child)
    }

    /// Change current node with its child, which is opposite to a given one. Other child is
    /// removed and returned.
    pub fn shrink_to_other(
        &mut self,
        for_removal: Direction,
    ) -> Result<Option<Box<Self>>, ARTNodeError> {
        match for_removal {
            Direction::Left => self.shrink_to(Direction::Right),
            Direction::Right => self.shrink_to(Direction::Left),
        }
    }

    pub fn display_analog(&self) -> ARTDisplayTree {
        let blank_marker = match self.is_blank {
            true => "blank ",
            false => "",
        };

        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string(),
            None => "None".to_string()
        };

        match self.is_leaf() {
            true => ARTDisplayTree::Leaf {
                public_key: format!(
                    "{}leaf of weight: {}, x: {}",
                    blank_marker,
                    self.weight,
                    pk_marker,
                ),
            },
            false => ARTDisplayTree::Inner {
                public_key: format!(
                    "{}node of weight: {}, x: {}",
                    blank_marker,
                    self.weight,
                    pk_marker,
                ),
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
                (left_node.public_key + right_node.public_key).into_affine(),
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
                (left_node.public_key + right_node.public_key).into_affine(),
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
                    .char_set(CharSet::DOUBLE_LINE)
            )
        )
    }
}

impl<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> PartialEq for ARTNode<G> {
    fn eq(&self, other: &Self) -> bool {
        match self.public_key != other.public_key
            || self.l != other.l
            || self.r != other.r
            || self.is_blank != other.is_blank
            // || self.weight != other.weight
        {
            true => false,
            false => true,
        }
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
        while let Some(current_node) = self.current_node {
            let return_item = (current_node, self.path.clone());

            if current_node.is_leaf() {
                loop {
                    match self.path.pop() {
                        Some((parent, last_direction)) => {
                            if last_direction == Direction::Right {
                                self.current_node = Some(parent);
                            } else if last_direction == Direction::Left {
                                self.path.push((parent, Direction::Right));
                                self.current_node =
                                    parent.get_right().map(|item| item.as_ref()).ok();
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
                self.current_node = current_node.get_left().map(|item| item.as_ref()).ok();
            }

            return Some(return_item);
        }

        None
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
        while let Some((item, path)) = self.inner_iter.next() {
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
        while let Some((item, _)) = self.inner_iter.next() {
            if item.is_leaf() {
                return Some(item);
            }
        }

        None
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
