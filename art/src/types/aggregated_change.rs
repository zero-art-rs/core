use crate::traits::RelatedData;
use crate::types::{Children, Direction};
use display_tree::DisplayTree;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub(crate) root: Option<ChangeAggregationNode<D>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregationNode<D>
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
    pub current_node: Option<&'a ChangeAggregationNode<D>>,
    pub path: Vec<(&'a ChangeAggregationNode<D>, Direction)>,
}

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
