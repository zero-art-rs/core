use crate::helper_tools::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::{CharSet, DisplayTree, Style, StyleBuilder, format_tree};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ARTNodeError {
    #[error("given parameters are invalid: {0}")]
    InvalidParameters(String),
    #[error("the method is callable only for leaves: {0}")]
    LeafOnly(String),
    #[error("the method is callable only for internal nodes: {0}")]
    InternalNodeOnly(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum Direction {
    NoDirection,
    Left,
    Right,
}

#[derive(DisplayTree)]
pub enum ARTDisplayTree {
    Leaf {
        #[node_label]
        public_key: String,
    },
    Inner {
        #[node_label]
        public_key: String,
        #[tree]
        left: Box<Self>,
        #[tree]
        right: Box<Self>,
    },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct ARTNode<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: G,
    pub l: Option<Box<Self>>,
    pub r: Option<Box<Self>>,
    pub is_temporal: bool,
    pub weight: usize,
}

impl<G: AffineRepr> ARTNode<G> {
    /// Creates a new ARTNode with the given public key and optional left and right children.
    ///
    /// The node must either be:
    /// - A leaf node: both l and r are None.
    /// - An inner node: both l and r are Some(...).
    ///
    /// Any other combination (e.g., only one child provided) is invalid and will return an error.
    pub fn new(
        public_key: G,
        l: Option<Box<ARTNode<G>>>,
        r: Option<Box<ARTNode<G>>>,
    ) -> Result<ARTNode<G>, ARTNodeError> {
        let weight = match (&l, &r) {
            (Some(l), Some(r)) => l.weight + r.weight, //internal node
            (None, None) => 1,                         // leaf node
            _ => {
                return Err(ARTNodeError::InvalidParameters(
                    "Cannot create a node with only one child".to_string(),
                ));
            }
        };

        Ok(ARTNode {
            public_key,
            l,
            r,
            is_temporal: false,
            weight,
        })
    }

    /// Creates a new ARTNode internal node with the given public key.
    pub fn new_internal_node(public_key: G, l: Box<ARTNode<G>>, r: Box<ARTNode<G>>) -> ARTNode<G> {
        let weight = l.weight + r.weight;

        ARTNode {
            public_key,
            l: Some(l),
            r: Some(r),
            is_temporal: false,
            weight,
        }
    }

    /// Creates a new ARTNode leaf with the given public key.
    pub fn new_leaf(public_key: G) -> ARTNode<G> {
        ARTNode {
            public_key,
            l: None,
            r: None,
            is_temporal: false,
            weight: 1,
        }
    }

    /// Checks it the node is leaf, i.e. both children are None.
    pub fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    /// Returns a reference to the left child node.
    pub fn get_left(&self) -> Result<&Box<ARTNode<G>>, ARTNodeError> {
        match &self.l {
            Some(l) => Ok(l),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a left child.".to_string(),
            )),
        }
    }

    /// If the node is a leaf node, converts the node to temporal, else return error
    pub fn make_temporal(&mut self, temporal_public_key: &G) -> Result<(), ARTNodeError> {
        if self.is_leaf() {
            self.set_public_key(temporal_public_key.clone());
            self.is_temporal = true;
            self.weight = 0;
            Ok(())
        } else {
            Err(ARTNodeError::LeafOnly(
                "Cannot convert internal node to temporal one.".to_string(),
            ))
        }
    }

    /// Returns a mutable reference to the left child node.
    pub fn get_mut_left(&mut self) -> Result<&mut Box<ARTNode<G>>, ARTNodeError> {
        match &mut self.l {
            Some(l) => Ok(l),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a left child.".to_string(),
            )),
        }
    }

    /// Returns a reference to the right child node.
    pub fn get_right(&self) -> Result<&Box<ARTNode<G>>, ARTNodeError> {
        match &self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a right child.".to_string(),
            )),
        }
    }

    /// Returns a mutable reference to the right child node.
    pub fn get_mut_right(&mut self) -> Result<&mut Box<ARTNode<G>>, ARTNodeError> {
        match &mut self.r {
            Some(r) => Ok(r),
            None => Err(ARTNodeError::InternalNodeOnly(
                "Leaf doesn't have a right child.".to_string(),
            )),
        }
    }

    /// Changes left child of inner node with a given one
    pub fn set_left(&mut self, other: ARTNode<G>) -> Result<(), ARTNodeError> {
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
    pub fn set_right(&mut self, other: ARTNode<G>) -> Result<(), ARTNodeError> {
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
    pub fn get_child(&self, child: &Direction) -> Result<&Box<ARTNode<G>>, ARTNodeError> {
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
    pub fn get_mut_child(
        &mut self,
        child: &Direction,
    ) -> Result<&mut Box<ARTNode<G>>, ARTNodeError> {
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
    pub fn get_other_child(&self, child: &Direction) -> Result<&Box<ARTNode<G>>, ARTNodeError> {
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
    ) -> Result<&mut Box<ARTNode<G>>, ARTNodeError> {
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
    pub fn extend(&mut self, other: ARTNode<G>) {
        let weight = other.weight + self.weight;

        let new_self = ARTNode {
            public_key: self.public_key.clone(),
            l: self.l.take(),
            r: self.r.take(),
            is_temporal: false,
            weight,
        };

        self.weight = other.weight + new_self.weight;
        self.l = Some(Box::new(new_self));
        self.r = Some(Box::new(other));
    }

    /// Changes values of the node with the values of the given one.
    pub fn replace_with(&mut self, other: ARTNode<G>) {
        self.set_public_key(other.get_public_key());
        self.l = other.l;
        self.r = other.r;
        self.is_temporal = other.is_temporal;
        self.weight = other.weight;
    }

    /// If the node is temporal, replace the node, else moves current node down to left,
    /// and append other node to the right.
    pub fn extend_or_replace(&mut self, other: ARTNode<G>) -> Result<(), ARTNodeError> {
        if !self.is_leaf() {
            return Err(ARTNodeError::LeafOnly(
                "Cannot extend an internal node.".to_string(),
            ));
        }

        match self.is_temporal {
            true => self.replace_with(other),
            false => self.extend(other),
        }

        Ok(())
    }

    /// Change current node with its child. Other child is removed and returned.
    pub fn shrink_to(&mut self, child: Direction) -> Result<Option<Box<ARTNode<G>>>, ARTNodeError> {
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

        Ok(other_child)
    }

    /// Change current node with its child, which is opposite to a given one. Other child is
    /// removed and returned.
    pub fn shrink_to_other(
        &mut self,
        for_removal: Direction,
    ) -> Result<Option<Box<ARTNode<G>>>, ARTNodeError> {
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
                    match self.is_temporal {
                        true => "temporal ",
                        false => "",
                    },
                    self.weight,
                    self.public_key.x().unwrap(),
                ),
            },
            false => ARTDisplayTree::Inner {
                public_key: format!(
                    "{}node of weight: {}, x: {}",
                    match self.is_temporal {
                        true => "temporal ",
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
            || self.is_temporal != other.is_temporal
            || self.weight != other.weight
        {
            true => false,
            false => true,
        }
    }
}
