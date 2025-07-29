use crate::errors::ARTNodeError;
use crate::types::{ARTDisplayTree, ARTNode, Direction, LeafIter, NodeIter, NodeIterWithPath};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::{CharSet, Style, StyleBuilder, format_tree};

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
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a left child.".to_string(),
            )),
        }
    }

    /// If the node is a leaf node, converts the node to blank, else return error
    pub fn make_blank(&mut self, temporary_public_key: &G) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            self.set_public_key(temporary_public_key.clone());
            self.is_blank = true;
            self.weight = 0;
            Ok(())
        } else {
            Err(ARTNodeError::LeafOnly(
                "Cannot convert internal node to blank one.".to_string(),
            ))
        }
    }

    /// Returns a mutable reference to the left child node.
    pub fn get_mut_left(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        match &mut self.l {
            Some(l) => Ok(l),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a left child.".to_string(),
            )),
        }
    }

    /// Returns a reference to the right child node.
    pub fn get_right(&self) -> Result<&Box<Self>, ARTNodeError> {
        match &self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a right child.".to_string(),
            )),
        }
    }

    /// Returns a mutable reference to the right child node.
    pub fn get_mut_right(&mut self) -> Result<&mut Box<Self>, ARTNodeError> {
        match &mut self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a right child.".to_string(),
            )),
        }
    }

    /// Changes left child of inner node with a given one
    pub fn set_left(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "Cant set left node for leaf. To append node use extend instead.".to_string(),
            ));
        }

        self.l = Some(Box::new(other));
        self.weight = self.get_right()?.weight + self.get_left()?.weight;

        Ok(())
    }

    /// Changes right child of inner node with a given one
    pub fn set_right(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "Cant set left node for leaf. To append node use extend instead.".to_string(),
            ));
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
        self.public_key = public_key;
    }

    /// Returns a reference on a child of a given inner node by a given direction to the child.
    pub fn get_child(&self, child: &Direction) -> Result<&Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "leaf node have no children.".to_string(),
            ));
        }

        match child {
            Direction::Left => Ok(self.get_left()?),
            Direction::Right => Ok(self.get_right()?),
            Direction::NoDirection => Err(ARTNodeError::InvalidParameters(
                "Unexpected direction".to_string(),
            )),
        }
    }

    /// Returns a mutable reference on a child of a given inner node by a given direction to
    /// the child.
    pub fn get_mut_child(&mut self, child: &Direction) -> Result<&mut Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "leaf node have no children.".to_string(),
            ));
        }

        match child {
            Direction::Left => Ok(self.get_mut_left()?),
            Direction::Right => Ok(self.get_mut_right()?),
            Direction::NoDirection => Err(ARTNodeError::InvalidParameters(
                "Unexpected direction".to_string(),
            )),
        }
    }

    /// Returns a reference on a child of a given inner node, which is located on the opposite
    /// side to the given direction.
    pub fn get_other_child(&self, child: &Direction) -> Result<&Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "leaf node have no children.".to_string(),
            ));
        }

        match child {
            Direction::Left => Ok(self.get_right()?),
            Direction::Right => Ok(self.get_left()?),
            Direction::NoDirection => Err(ARTNodeError::InvalidParameters(
                "unexpected direction".into(),
            )),
        }
    }

    /// Returns a mutable reference on a child of a given inner node, which is located on the
    /// opposite side to the given direction.
    pub fn get_mut_other_child(
        &mut self,
        child: &Direction,
    ) -> Result<&mut Box<Self>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "leaf node have no children.".to_string(),
            ));
        }

        match child {
            Direction::Left => Ok(self.r.as_mut().unwrap()),
            Direction::Right => Ok(self.l.as_mut().unwrap()),
            Direction::NoDirection => Err(ARTNodeError::InvalidParameters(
                "Unexpected direction".to_string(),
            )),
        }
    }

    /// Move current node down to left child, and append other node to the right. The current node
    /// becomes internal.
    pub fn extend(&mut self, other: Self) {
        let weight = other.weight + self.weight;

        let new_self = Self {
            public_key: self.public_key.clone(),
            l: self.l.take(),
            r: self.r.take(),
            is_blank: false,
            weight,
            metadata: self.metadata.clone(),
        };

        self.weight = other.weight + new_self.weight;
        self.l = Some(Box::new(new_self));
        self.r = Some(Box::new(other));
        self.metadata = None
    }

    /// Changes values of the node with the values of the given one.
    pub fn replace_with(&mut self, other: Self) {
        self.set_public_key(other.get_public_key());
        self.l = other.l;
        self.r = other.r;
        self.is_blank = other.is_blank;
        self.weight = other.weight;
        self.metadata = other.metadata;
    }

    /// If the node is temporary, replace the node, else moves current node down to left,
    /// and append other node to the right.
    pub fn extend_or_replace(&mut self, other: Self) -> Result<(), ARTNodeError> {
        if !self.is_leaf() {
            return Err(ARTNodeError::LeafOnly(
                "Cannot extend an internal node.".to_string(),
            ));
        }

        match self.is_blank {
            true => self.replace_with(other),
            false => self.extend(other),
        }

        Ok(())
    }

    /// Change current node with its child. Other child is removed and returned.
    pub fn shrink_to(&mut self, child: Direction) -> Result<Option<Box<Self>>, ARTNodeError> {
        if self.is_leaf() {
            return Err(ARTNodeError::InternalNodeOnly(
                "Cannot shrink a leaf node.".to_string(),
            ));
        }

        let (new_self, other_child) = match child {
            Direction::Left => (self.l.take(), self.r.take()),
            Direction::Right => (self.r.take(), self.l.take()),
            _ => {
                return Err(ARTNodeError::InvalidParameters(
                    "Unexpected direction".into(),
                ));
            }
        };

        let mut new_self = new_self.unwrap();

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
            _ => Err(ARTNodeError::InvalidParameters(
                "Unexpected direction".into(),
            )),
        }
    }

    pub fn display_analog(&self) -> ARTDisplayTree {
        match self.is_leaf() {
            true => ARTDisplayTree::Leaf {
                public_key: format!(
                    "{}leaf of weight: {}, x: {}",
                    match self.is_blank {
                        true => "temporary ",
                        false => "",
                    },
                    self.weight,
                    self.public_key.x().unwrap(),
                ),
            },
            false => ARTDisplayTree::Inner {
                public_key: format!(
                    "{}node of weight: {}, x: {}",
                    match self.is_blank {
                        true => "blank ",
                        false => "",
                    },
                    self.weight,
                    self.public_key.x().unwrap(),
                ),
                left: Box::new(self.get_left().unwrap().display_analog()),
                right: Box::new(self.get_right().unwrap().display_analog()),
            },
        }
    }

    pub fn print_as_formated_tree(&self) {
        println!(
            "{}",
            format_tree!(
                self.display_analog(),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::DOUBLE_LINE)
            )
        );
    }
}

impl<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> PartialEq for ARTNode<G> {
    fn eq(&self, other: &Self) -> bool {
        match self.public_key != other.public_key
            || self.l != other.l
            || self.r != other.r
            || self.is_blank != other.is_blank
            || self.weight != other.weight
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

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, G> NodeIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
        NodeIter { stack: vec![root] }
    }
}

impl<'a, G> Iterator for NodeIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ARTNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.stack.pop() {
            if let Ok(right) = node.get_right() {
                self.stack.push(right);
            }

            if let Ok(left) = node.get_left() {
                self.stack.push(left);
            }

            Some(node)
        } else {
            None
        }
    }
}

/// LeafIter iterates ove leaves from left most to right most
impl<'a, G> LeafIter<'a, G>
where
    G: AffineRepr,
{
    pub fn new(root: &'a ARTNode<G>) -> Self {
        LeafIter { stack: vec![root] }
    }
}

impl<'a, G> Iterator for LeafIter<'a, G>
where
    G: AffineRepr,
{
    type Item = &'a ARTNode<G>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.stack.len() != 0 {
            if let Some(node) = self.stack.pop() {
                if let Ok(right) = node.get_right() {
                    self.stack.push(right);
                }

                if let Ok(left) = node.get_left() {
                    self.stack.push(left);
                }

                if node.is_leaf() {
                    return Some(node);
                }
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
