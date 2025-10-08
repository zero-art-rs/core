use crate::helper_tools::{ark_de, ark_se};
use crate::types::Direction;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::DisplayTree;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

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

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Eq, PartialEq)]
#[serde(bound = "")]
pub enum LeafStatus {
    Active,
    PendingRemoval,
    Blank,
}

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(bound = "")]
pub enum ARTNode<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    Leaf {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        status: LeafStatus,
        metadata: Vec<u8>,
    },
    Internal {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        public_key: G,
        l: Box<ARTNode<G>>,
        r: Box<ARTNode<G>>,
        weight: usize,
    },
}

pub struct NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub current_node: Option<&'a ARTNode<G>>,
    pub path: Vec<(&'a ARTNode<G>, Direction)>,
}

pub struct LeafIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}

pub struct NodeIter<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}

pub struct LeafIter<'a, G>
where
    G: AffineRepr,
{
    pub inner_iter: NodeIterWithPath<'a, G>,
}
