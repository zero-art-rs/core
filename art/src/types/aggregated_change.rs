use crate::traits::RelatedData;
use crate::types::{BranchChangesTypeHint, Children, Direction};
use ark_ec::AffineRepr;
use curve25519_dalek::Scalar;
use display_tree::DisplayTree;

#[derive(DisplayTree, Debug, Clone)]
pub enum AggregationDisplayTree {
    Leaf {
        #[node_label]
        public_key: String,
    },
    Route {
        #[node_label]
        public_key: String,
        #[tree]
        child: Box<Self>,
    },
    Node {
        #[node_label]
        public_key: String,
        #[tree]
        left: Box<Self>,
        #[tree]
        right: Box<Self>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub children: Children<Self>,

    pub data: D,
}

#[derive(Debug, Clone)]
pub struct AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub current_node: Option<&'a ChangeAggregation<D>>,
    pub path: Vec<(&'a ChangeAggregation<D>, Direction)>,
}
