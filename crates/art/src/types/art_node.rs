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

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct ARTNode<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: G,
    pub l: Option<Box<Self>>,
    pub r: Option<Box<Self>>,
    pub is_blank: bool,
    pub weight: usize,
    pub metadata: Option<Vec<u8>>,
}

pub struct NodeIterWithPath<'a, G>
where
    G: AffineRepr,
{
    pub current_node: Option<&'a ARTNode<G>>,
    pub path: Vec<(&'a ARTNode<G>, Direction)>,
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
